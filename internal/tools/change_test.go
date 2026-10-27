package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/change/hash"
	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/inventory"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

var writeRule = config.Rule{Match: config.Match{Kind: "default"}, WriteRef: "ssh-write"}

// startChange serves a stateful fake IOS-XE dev1 with archive path set,
// whose running config gives the connect address to GigabitEthernet0/0.
// The read login is refused unless su.opt says otherwise, so anything that
// works used the write ref.
func startChange(t *testing.T, su setup) (*env, *sshfake.Device) {
	t.Helper()
	dev := &sshfake.Device{}
	su.eng = &sshfake.Engine{Hostname: "dev1", Device: dev, Commands: map[string]string{"terminal width 512": "", "terminal length 0": ""}}
	if su.opt == (sshfake.Options{}) {
		su.opt = sshfake.Options{FailUser: "mcp"}
	}
	su.platform = "cisco_iosxe"
	e := startWith(t, su)
	dev.Running = string(must(os.ReadFile(napalm+"ios_show_running_config.txt"))) + fakeSecrets +
		"interface GigabitEthernet0/0\n ip address " + e.fake.Host + " 255.0.0.0\narchive\n path flash:archive\n"
	dev.Startup = dev.Running
	return e, dev
}

func plan(lines ...string) map[string]any {
	return map[string]any{"action": "plan", "device": "dev1", "reason": "add the users VLAN", "lines": lines}
}

func TestChangeAbsentByDefault(t *testing.T) {
	e := start(t, nil, sshfake.Options{})
	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Name == "network_change" {
			t.Fatal("network_change listed without --allow-config")
		}
	}
	r, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "network_change", Arguments: plan("vlan 10")})
	if err == nil && !r.IsError {
		t.Fatal("network_change ran without --allow-config")
	}
	if out, _ := e.call(t, "network_status", nil); out["changes"] != nil {
		t.Fatalf("status shows changes without --allow-config: %v", out)
	}
}

func TestChangePlan(t *testing.T) {
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	run := dev.Running
	res, _ := e.cs.ListTools(context.Background(), nil)
	i := slices.IndexFunc(res.Tools, func(tl *mcp.Tool) bool { return tl.Name == "network_change" })
	if i < 0 {
		t.Fatal("network_change not listed")
	}
	if a := res.Tools[i].Annotations; a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Fatalf("annotations %+v", a)
	}

	out, errText := e.call(t, "network_change", plan("router bgp 64496", "  neighbor 192.0.2.2   password fakepw", "vlan 10", " name users"))
	if errText != "" {
		t.Fatal(errText)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(fmt.Sprint(out["plan_id"])) || out["pre_hash"] != hash.Sum(run) ||
		out["diff"] != "+ router bgp 64496\n+ neighbor 192.0.2.2 password <redacted>\n+ vlan 10\n+ name users" ||
		out["expires"] == nil || out["device"] != "dev1" || out["_redactions"] != 1.0 {
		t.Fatalf("plan: %v", out)
	}
	if got := e.commands(); !slices.Equal(got, []string{"terminal width 512", "terminal length 0", "show running-config"}) {
		t.Fatalf("plan sent %q", got)
	}
	a := e.audit.String()
	for _, want := range []string{`"event":"plan"`, `"outcome":"ok"`, `"cred_ref":"ssh-write"`, `"username":"mcp-write"`, `"host_key":"SHA256:`,
		`"plan_id":"` + fmt.Sprint(out["plan_id"]), `"pre_hash":"` + hash.Sum(run), `"reason":"add the users VLAN"`, `"platform":"iosxe"`, "password \\u003credacted"} {
		if !strings.Contains(a, want) {
			t.Errorf("audit lacks %s: %s", want, a)
		}
	}
	if strings.Contains(a, "fakepw") || strings.Contains(fmt.Sprint(out), "fakecomm") {
		t.Fatal("secret in audit or result")
	}

	st, _ := e.call(t, "network_change", map[string]any{"action": "status"})
	if fmt.Sprint(st["changes"]) != "map[max_pending_changes:1 pending_changes:0 pending_plans:1]" || len(st["plans"].([]any)) != 1 {
		t.Fatalf("status: %v", st)
	}
	if ns, _ := e.call(t, "network_status", nil); fmt.Sprint(ns["changes"]) != "map[max_pending_changes:1 pending_changes:0 pending_plans:1]" ||
		fmt.Sprint(ns["groups"]) != "[core cli export change]" {
		t.Fatalf("network_status: %v", ns)
	}
}

func TestChangeRefusals(t *testing.T) {
	e, _ := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	for _, tc := range []struct {
		args    map[string]any
		outcome string
		device  bool // the running config was read first
	}{
		{plan("vlan 10", "userna x"), "denied", false},
		{plan("do show run"), "denied", false},
		{plan("interface range gi1/0/1 - 2", "int gi0/0"), "denied", true},
		{plan("vlan 10\nusername x"), "denied", false},
		{map[string]any{"action": "plan", "device": "dev1", "lines": []string{"vlan 10"}}, "refused", false},
		{map[string]any{"action": "plan", "device": "dev1", "lines": []string{"vlan 10"}, "reason": " "}, "refused", false},
		{map[string]any{"action": "plan", "device": "dev-outside", "lines": []string{"vlan 10"}, "reason": "r"}, "refused", false},
		{map[string]any{"action": "plan", "device": "dev-name", "lines": []string{"vlan 10"}, "reason": "r"}, "refused", false}, // generic driver
	} {
		e.audit.Reset()
		before := len(e.commands())
		if _, errText := e.call(t, "network_change", tc.args); errText == "" {
			t.Errorf("%v accepted", tc.args)
		}
		if !strings.Contains(e.audit.String(), `"outcome":"`+tc.outcome+`"`) {
			t.Errorf("%v: audit %s", tc.args, e.audit)
		}
		if read := len(e.commands()) > before; read != tc.device {
			t.Errorf("%v: device read %v", tc.args, read)
		}
	}
	if st, _ := e.call(t, "network_change", map[string]any{"action": "status"}); st["plans"] != nil {
		t.Fatalf("a refused plan was stored: %v", st)
	}
}

func TestChangeDrivers(t *testing.T) {
	t.Cleanup(func() { inventory.AdhocPort = 22 })
	for _, platform := range []string{"cisco_ios", "", "adhoc"} {
		su := setup{allowConfig: true, eng: &sshfake.Engine{Hostname: "dev1"}, platform: platform,
			rules: []config.Rule{writeRule, {Match: config.Match{Kind: "adhoc"}, WriteRef: "ssh-write"}}}
		args := plan("vlan 10")
		if platform == "adhoc" {
			su.adhoc, su.platform, args["device"] = true, "", "127.0.0.1"
		}
		e := startWith(t, su)
		inventory.AdhocPort = e.fake.Port
		if _, errText := e.call(t, "network_change", args); !strings.Contains(errText, "cannot be changed") && !strings.Contains(errText, "driver") {
			t.Errorf("%q: %s", platform, errText)
		}
		if len(e.commands()) != 0 {
			t.Errorf("%q: device contacted", platform)
		}
	}
}

func TestChangeNoWriteRef(t *testing.T) {
	e, _ := startChange(t, setup{allowConfig: true}) // read_ref only: never a fallback
	if _, errText := e.call(t, "network_change", plan("vlan 10")); !strings.Contains(errText, "write_ref") {
		t.Fatal(errText)
	}
	if len(e.commands()) != 0 || len(e.fake.Received()) != 0 {
		t.Fatal("the read ref was used to plan")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestChangeAuditFailClosed(t *testing.T) {
	e, _ := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}, auditW: failWriter{}})
	if _, errText := e.call(t, "network_change", plan("vlan 10")); !strings.Contains(errText, "audit") {
		t.Fatalf("plan with a failing audit log: %q", errText)
	}
	if st, _ := e.call(t, "network_change", map[string]any{"action": "status"}); st["plans"] != nil {
		t.Fatalf("plan stored: %v", st)
	}
}
