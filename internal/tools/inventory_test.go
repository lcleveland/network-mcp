package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/sshfake"
)

// two sources: the first gives dev1 its address, the second its platform and tags
const second = `
- {name: DEV1, platform: cisco_nxos, tags: [core, lab]}
- {name: dev-noaddr, platform: cisco_iosxe, tags: [edge]}
- {name: "evil\e[31m‮X", address: 127.0.0.2}
`

func startInventory(t *testing.T) *env {
	t.Helper()
	return startWith(t, setup{eng: &sshfake.Engine{Hostname: "dev1"}, second: second})
}

func names(out map[string]any) string {
	var s []string
	rows, _ := out["rows"].([]any)
	for _, r := range rows {
		s = append(s, fmt.Sprint(r.(map[string]any)["name"]))
	}
	return strings.Join(s, " ")
}

func TestInventoryList(t *testing.T) {
	e := startInventory(t)
	for args, want := range map[string]string{
		`{}`:                              "dev-far dev-name dev-noaddr dev-outside dev1 evilX",
		`{"name": "DEV-*"}`:               "dev-far dev-name dev-noaddr dev-outside",
		`{"name": "dev-[fn]a*"}`:          "dev-far dev-name",
		`{"platform": "CISCO_IOSXE"}`:     "dev-noaddr",
		`{"driver": "nxos"}`:              "dev1",
		`{"driver": "generic_ssh"}`:       "dev-far dev-name dev-outside evilX",
		`{"tag": "Lab"}`:                  "dev1",
		`{"tag": "edge", "name": "dev1"}`: "",
	} {
		var a map[string]any
		json.Unmarshal([]byte(args), &a)
		a["action"] = "list"
		out, errText := e.call(t, "network_inventory", a)
		if errText != "" || out["total"] != float64(len(strings.Fields(want))) {
			t.Fatalf("%s: %v %s", args, out, errText)
		}
		if got := names(out); got != want {
			t.Errorf("%s: %q, want %q", args, got, want)
		}
	}

	out, _ := e.call(t, "network_inventory", map[string]any{"action": "list", "name": "dev1", "fields": []string{"tags", "provenance"}})
	row := out["rows"].([]any)[0].(map[string]any)
	if len(row) != 3 || fmt.Sprint(row["tags"]) != "[core lab]" || fmt.Sprint(row["provenance"]) != "map[address:file opt_in:file platform:second port:file tags:second]" {
		t.Fatalf("fields: %v", row)
	}
	for _, args := range []map[string]any{{"fields": []string{"password"}}, {"name": "["}, {"action": "drop"}} {
		if args["action"] == nil {
			args["action"] = "list"
		}
		if _, errText := e.call(t, "network_inventory", args); errText == "" {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestInventoryLimit(t *testing.T) {
	var yaml strings.Builder
	for i := range 250 {
		fmt.Fprintf(&yaml, "- {name: sw%03d, address: 127.0.1.%d}\n", i, i%250)
	}
	e := startWith(t, setup{eng: &sshfake.Engine{Hostname: "dev1"}, second: yaml.String()})
	for limit, shown := range map[int]int{0: 50, 7: 7, 1000: 200} {
		out, _ := e.call(t, "network_inventory", map[string]any{"action": "list", "name": "sw*", "limit": limit})
		tr, _ := out["_truncation"].(map[string]any)
		if len(out["rows"].([]any)) != shown || out["total"] != 250.0 ||
			fmt.Sprint(tr) != fmt.Sprintf("map[hint:narrow with name/platform/tag reason:rows shown:%d total:250]", shown) {
			t.Errorf("limit %d: %d rows, %v", limit, len(out["rows"].([]any)), tr)
		}
	}
	if out, _ := e.call(t, "network_inventory", map[string]any{"action": "list", "name": "sw00*"}); out["_truncation"] != nil {
		t.Errorf("under the limit: %v", out["_truncation"])
	}
}

func TestInventoryGet(t *testing.T) {
	e := startInventory(t)
	out, _ := e.call(t, "network_inventory", map[string]any{"action": "get", "name": "dev1"})
	dev, gate := out["device"].(map[string]any), fmt.Sprint(out["gate"])
	if dev["read_ref"] != "ssh-read" || dev["driver"] != "nxos" || fmt.Sprint(dev["provenance"]) != "map[address:file opt_in:file platform:second port:file tags:second]" ||
		gate != "map[host_key_pinned:true in_prefix:true opt_in:true prefix:127.0.0.0/8]" {
		t.Fatalf("dev1: %v", out)
	}

	out, _ = e.call(t, "network_inventory", map[string]any{"action": "get", "name": "dev-outside"})
	if gate := fmt.Sprint(out["gate"]); gate != "map[host_key_pinned:false in_prefix:false in_prefix_reason:device dev-outside address 192.0.2.1 is outside management_prefixes opt_in:true]" {
		t.Fatalf("outside: %v", gate)
	}
	out, _ = e.call(t, "network_inventory", map[string]any{"action": "get", "name": "dev-noaddr"})
	if gate := fmt.Sprint(out["gate"]); gate != "map[host_key_pinned:false in_prefix:false in_prefix_reason:no address opt_in:true reachable_reason:no source gives an address and resolve_names is off]" {
		t.Fatalf("no address: %v", gate)
	}
	// the refusing gate is named in network_status too
	if out, _ = e.call(t, "network_status", map[string]any{"device": "dev-noaddr"}); checks(out) != "reachable:false" {
		t.Fatalf("status: %v", out)
	}

	os.WriteFile(e.fake.KnownHosts, must(os.ReadFile(sshfake.WrongKnownHosts(t, "127.0.0.9:22"))), 0o600)
	if out, _ = e.call(t, "network_inventory", map[string]any{"action": "get", "name": "dev1"}); out["gate"].(map[string]any)["host_key_pinned"] != false {
		t.Fatalf("unpinned: %v", out["gate"])
	}

	res, _ := e.call(t, "network_inventory", map[string]any{"action": "get", "name": "dev-name"})
	if b, _ := json.Marshal(res); strings.Contains(string(b), e.deps.Config.CredentialsDir) {
		t.Fatalf("credential path in result: %s", b)
	}
	if _, errText := e.call(t, "network_inventory", map[string]any{"action": "get", "name": "nope"}); !strings.Contains(errText, "unknown device") {
		t.Fatalf("unknown: %s", errText)
	}
}

func TestInventoryUntrustedName(t *testing.T) {
	e := startInventory(t)
	out, _ := e.call(t, "network_inventory", map[string]any{"action": "list", "name": "evil*"})
	if names(out) != "evilX" || !strings.Contains(fmt.Sprint(out["_untrusted"]), "rows[].name") {
		t.Fatalf("list: %v", out)
	}
	out, _ = e.call(t, "network_inventory", map[string]any{"action": "get", "name": "evil\x1b[31m‮X"})
	if out["device"].(map[string]any)["name"] != "evilX" || !strings.Contains(fmt.Sprint(out["_untrusted"]), "device.name") {
		t.Fatalf("get: %v", out)
	}
}

func TestInventoryBytes(t *testing.T) {
	var yaml strings.Builder
	tags := "[" + strings.TrimSuffix(strings.Repeat(strings.Repeat("t", 250)+", ", 30), ", ") + "]"
	for i := range 20 {
		fmt.Fprintf(&yaml, "- {name: fat%02d, tags: %s}\n", i, tags)
	}
	e := startWith(t, setup{eng: &sshfake.Engine{Hostname: "dev1"}, second: yaml.String()})
	out, _ := e.call(t, "network_inventory", map[string]any{"action": "list", "name": "fat*"})
	b, _ := json.Marshal(out)
	if tr, _ := out["_truncation"].(map[string]any); len(b) > 60<<10 || tr["reason"] != "bytes" || tr["total"] != 20.0 {
		t.Fatalf("%d bytes, %v", len(b), out["_truncation"])
	}
}
