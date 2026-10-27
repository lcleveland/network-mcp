package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/mib"
	"github.com/lcleveland/network-mcp/internal/snmpfake"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

func TestMain(m *testing.M) {
	if err := mib.Load(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func startSNMP(t *testing.T) *env {
	t.Helper()
	var files []string
	for _, f := range []string{"system", "if-mib", "entity", "denied"} {
		files = append(files, "../../testdata/snmp/"+f+".snmprec")
	}
	return startWith(t, setup{eng: &sshfake.Engine{Hostname: "dev1"}, snmp: &snmpfake.Options{Files: files}})
}

func TestSNMP(t *testing.T) {
	e := startSNMP(t)
	out, errText := e.call(t, "network_snmp", map[string]any{"action": "get", "device": "dev1",
		"oids": []string{"sysName.0", "IF-MIB::ifDescr.3", "1.3.6.1.2.1.2.2.1.6.1", "1.3.6.1.2.1.1.42.0"}})
	b, _ := json.Marshal(out)
	for _, want := range []string{`"value":"dev1.example.net"`, `"name":"IF-MIB::ifDescr.3"`, `"value":"GigabitEthernet1/0/3"`,
		`"value":"0x00005e005301"`, `"type":"NoSuchObject","value":null`, `"_untrusted":["rows"]`, `"warnings":["1.3.6.1.2.1.1.42.0: NoSuchObject"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("get: missing %s in %s %s", want, b, errText)
		}
	}

	out, _ = e.call(t, "network_snmp", map[string]any{"action": "bulkwalk", "device": "dev1", "oid": "IF-MIB::ifTable"})
	tr, _ := out["_truncation"].(map[string]any)
	if tr["reason"] != "rows" || tr["shown"] != float64(500) || !strings.HasPrefix(fmt.Sprint(tr["hint"]), "use after: 1.3.6.1.2.1.2.2.1.7.") {
		t.Fatalf("truncation: %v", tr)
	}
	after := strings.TrimPrefix(tr["hint"].(string), "use after: ")
	out, _ = e.call(t, "network_snmp", map[string]any{"action": "walk", "device": "dev1", "oid": "ifTable", "after": after, "max_rows": 5})
	rows := out["rows"].([]any)
	if first := rows[0].(map[string]any)["oid"].(string); len(rows) != 5 || first == after || !strings.HasPrefix(first, "1.3.6.1.2.1.2.2.1.7.") {
		t.Fatalf("resume after %s: %v", after, rows)
	}

	out, _ = e.call(t, "network_snmp", map[string]any{"action": "bulkwalk", "device": "dev1", "oid": "1.3.6.1.6.3"})
	if b, _ := json.Marshal(out); strings.Contains(string(b), "planted") || !strings.Contains(string(b), "withheld") {
		t.Errorf("denied rows returned: %s", b)
	}

	out, _ = e.call(t, "network_snmp", map[string]any{"action": "resolve", "oids": []string{"IF-MIB::ifDescr", "1.3.6.1.2.1.2.2.1.2"}})
	if fmt.Sprint(out["resolved"]) != "[map[input:IF-MIB::ifDescr name:IF-MIB::ifDescr oid:1.3.6.1.2.1.2.2.1.2] map[input:1.3.6.1.2.1.2.2.1.2 name:IF-MIB::ifDescr oid:1.3.6.1.2.1.2.2.1.2]]" {
		t.Errorf("resolve: %v", out)
	}
}

func TestSNMPRefusals(t *testing.T) {
	e := startSNMP(t)
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"action": "get", "device": "dev1", "oids": []string{"1.3.6.1.6.3.18.1.1.1.2.116.49"}}, "denied subtree"},
		{map[string]any{"action": "walk", "device": "dev1", "oid": "SNMP-USER-BASED-SM-MIB::usmUserTable"}, "denied subtree"},
		{map[string]any{"action": "bulkwalk", "device": "dev1", "oid": "1.3.6.1.6.3", "after": "1.3.6.1.6.3.18.1"}, "denied subtree"},
		{map[string]any{"action": "walk", "device": "dev1", "oid": "system", "after": "1.3.6.1.2.1.2.1"}, "not inside"},
		{map[string]any{"action": "walk", "device": "dev1", "oid": "system", "max_rows": 5001}, "max_rows"},
		{map[string]any{"action": "get", "device": "dev1", "oids": make([]string, 17)}, "1 to 16"},
		{map[string]any{"action": "get", "device": "dev1", "oids": []string{"noSuchName.0"}}, "unknown MIB name"},
		{map[string]any{"action": "get", "device": "dev-name", "oids": []string{"sysName.0"}}, "no SNMP rule"},
		{map[string]any{"action": "get", "device": "dev-outside", "oids": []string{"sysName.0"}}, "outside"},
		{map[string]any{"action": "set", "device": "dev1"}, "action"},
	} {
		e.audit.Reset()
		if _, errText := e.call(t, "network_snmp", tc.args); !strings.Contains(errText, tc.want) {
			t.Errorf("%v: %q, want %q", tc.args, errText, tc.want)
		}
		if tc.want == "denied subtree" && !strings.Contains(e.audit.String(), `"event":"snmp_gate"`) {
			t.Errorf("%v: no audit line: %s", tc.args, e.audit)
		}
	}
}

// An SNMP-only device (snmp rule, no read_ref) is read over SNMP; the SSH
// tools refuse it and network_status skips the SSH checks.
func TestSNMPOnly(t *testing.T) {
	e := startSNMP(t)
	// the default rule now matches only dev-outside: dev1 keeps just its SNMP rule
	e.deps.Config.File.Rules[0].Match = config.Match{Kind: "device", Value: "dev-outside"}
	if out, errText := e.call(t, "network_snmp", map[string]any{"action": "get", "device": "dev1", "oids": []string{"sysName.0"}}); !strings.Contains(fmt.Sprint(out["rows"]), "dev1.example.net") {
		t.Errorf("snmp: %v %s", out, errText)
	}
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"network_show", map[string]any{"device": "dev1", "command": "show version"}},
		{"network_config", map[string]any{"action": "get", "device": "dev1", "source": "running"}},
	} {
		if _, errText := e.call(t, c.tool, c.args); !strings.Contains(errText, "no rule gives dev1 a read_ref, so SSH is disabled") {
			t.Errorf("%s: %q", c.tool, errText)
		}
	}
	if out, _ := e.call(t, "network_status", map[string]any{"device": "dev1"}); checks(out) != "management_prefix:true snmp:true" {
		t.Errorf("status: %v", out)
	}
	if out, _ := e.call(t, "network_inventory", map[string]any{"action": "get", "name": "dev1"}); out["gate"].(map[string]any)["reachable_reason"] != nil {
		t.Errorf("inventory: %v", out)
	}
	// neither read_ref nor snmp: unreachable for every tool
	if _, errText := e.call(t, "network_snmp", map[string]any{"action": "get", "device": "dev-name", "oids": []string{"sysName.0"}}); !strings.Contains(errText, "no rule gives a read_ref or snmp") {
		t.Errorf("dev-name: %q", errText)
	}
}

func TestSNMPStatus(t *testing.T) {
	e := startSNMP(t)
	out, _ := e.call(t, "network_status", nil)
	if fmt.Sprint(out["groups"]) != "[core cli snmp export]" {
		t.Errorf("groups: %v", out["groups"])
	}
	out, _ = e.call(t, "network_status", map[string]any{"device": "dev1"})
	if c := checks(out); !strings.HasSuffix(c, "prompt:true snmp:true") || !strings.Contains(fmt.Sprint(out["checks"]), "sysUpTime 123456789") {
		t.Errorf("status: %v", out)
	}
}
