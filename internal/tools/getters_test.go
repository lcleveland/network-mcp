package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

const ntc, napalm = "../../testdata/third_party/ntc-templates/", "../../testdata/third_party/napalm/"

// text is what the output pipeline makes of a raw fixture.
func text(raw string) string {
	s, _, _ := (*output.Filter)(nil).Text(strings.TrimRight(raw, "\n "), false)
	return s
}

func TestGettersIOSXE(t *testing.T) {
	files := map[string]string{
		"facts": ntc + "cisco_ios_show_version.raw", "inventory": ntc + "cisco_ios_show_inventory.raw",
		"environment": napalm + "ios_show_env_temperature_status.txt", "interfaces": ntc + "cisco_ios_show_interfaces2.raw",
		"interfaces_ip": ntc + "cisco_ios_show_ip_interface3.raw", "vlans": napalm + "ios_show_vlan_brief.txt",
		"lldp_neighbors": ntc + "cisco_ios_show_lldp_neighbors_detail1.raw", "cdp_neighbors": ntc + "cisco_ios_show_cdp_neighbors_detail2.raw",
		"arp_table": ntc + "cisco_ios_show_ip_arp.raw", "mac_address_table": ntc + "cisco_ios_show_mac-address-table.raw",
		"routes": ntc + "cisco_ios_show_ip_route1.raw", "bgp_neighbors": ntc + "cisco_ios_show_ip_bgp_summary.raw",
	}
	cmds := map[string]string{"terminal width 512": "", "terminal length 0": "", "who": "mcp vty 0"}
	for g, f := range files {
		cmds[platform.Profiles["iosxe"][g]] = string(must(os.ReadFile(f)))
	}
	// a site's own platform value, mapped explicitly, with a read_allow
	e := startWith(t, setup{eng: &sshfake.Engine{Hostname: "dev1", Commands: cmds}, platform: "C9K",
		platforms: map[string]platform.Config{"c9k": {Driver: platform.IOSXE, Profile: "iosxe", ReadAllow: []string{"who"}}}})
	var sent []string
	for g := range files {
		cmd := platform.Profiles["iosxe"][g]
		out, errText := e.call(t, "network_show", map[string]any{"device": "dev1", "getter": g})
		if errText != "" || out["output"] != text(cmds[cmd]) || out["command"] != cmd || out["parsed"] != false {
			t.Errorf("%s: %.300v %s", g, out, errText)
		}
		sent = append(sent, cmd)
	}
	if out, _ := e.call(t, "network_show", map[string]any{"device": "dev1", "command": "who"}); out["output"] != "mcp vty 0" {
		t.Errorf("read_allow: %v", out)
	}
	if out, _ := e.call(t, "network_show", map[string]any{"device": "dev1", "command": "show bogus"}); !strings.Contains(fmt.Sprint(out["device_error"]), "% Invalid input") || out["output"] != nil {
		t.Errorf("device error: %v", out)
	}
	// each call is its own session, so the settings precede every command
	var want []string
	for _, c := range append(sent, "who", "show bogus") {
		want = append(want, "terminal width 512", "terminal length 0", c)
	}
	if got := e.commands(); !slices.Equal(got, want) {
		t.Errorf("sent %q\nwant %q", got, want)
	}
}

func TestGettersNXOS(t *testing.T) {
	files := map[string]string{
		"facts": napalm + "nxos_show_version.json", "inventory": napalm + "nxos_show_inventory.json",
		"environment": napalm + "nxos_show_environment.json", "interfaces": napalm + "nxos_show_interface.json",
		"interfaces_ip": napalm + "nxos_show_ip_interface.json", "vlans": napalm + "nxos_show_vlan_brief.json",
		"arp_table": napalm + "nxos_show_ip_arp.json", "mac_address_table": napalm + "nxos_show_mac_address-table.json",
		"bgp_neighbors": napalm + "nxos_show_bgp_all_summary_vrf_all.json",
		// text: no public JSON capture, so these also test the fallback
		"lldp_neighbors": napalm + "nxos_show_lldp_neighbors_detail.txt", "cdp_neighbors": ntc + "cisco_nxos_show_cdp_neighbors_detail2.raw",
		"routes": ntc + "cisco_nxos_show_ip_route_vrf2.raw",
	}
	var big strings.Builder
	big.WriteString(`{"rows": [`)
	for i := range 2000 {
		fmt.Fprintf(&big, `{"if": "Ethernet1/%d", "state": "up"},`, i)
	}
	big.WriteString(`{"if": "mgmt0", "state": "up"}]}`)
	cmds := map[string]string{
		"terminal width 511": "", "terminal length 0": "",
		// hand-made, shaped like NX-OS show snmp | json
		"show snmp | json":             `{"sys_contact": "noc", "TABLE_snmp_community": {"ROW_snmp_community": [{"community_name": "fakecomm", "grouporaccess": "network-operator"}]}}`,
		"show system resources | json": big.String(),
		"show clock | json":            `{"simple_time": "12:00:00"}`,
		"show hostname | json":         "dev1",
		// seen on a real 9.3(3) switch: shell noise ahead of the JSON
		"show uptime | json": "sh: /mnt/pss/patch_debug.log: Read-only file system\n{\"sys_up_days\": \"1359\"}",
	}
	for g, f := range files {
		cmds[platform.Profiles["nxos"][g]+" | json"] = string(must(os.ReadFile(f)))
	}
	e := startWith(t, setup{eng: &sshfake.Engine{Hostname: "dev1", Profile: sshfake.NXOS, Commands: cmds}, platform: "cisco_nxos"})
	for g, f := range files {
		cmd := platform.Profiles["nxos"][g]
		out, errText := e.call(t, "network_show", map[string]any{"device": "dev1", "getter": g})
		if errText != "" || out["command"] != cmd {
			t.Errorf("%s: %v %s", g, out, errText)
			continue
		}
		var want any
		if json.Unmarshal(must(os.ReadFile(f)), &want) != nil { // not JSON: raw text fallback
			if out["parsed"] != false || out["output"] != text(cmds[cmd+" | json"]) || out["data"] != nil {
				t.Errorf("%s fallback: %v", g, out)
			}
			continue
		}
		want, _ = output.RedactJSON(want)
		if out["parsed"] != true || !reflect.DeepEqual(out["data"], want) || out["output"] != nil || fmt.Sprint(out["_untrusted"]) != "[data]" {
			t.Errorf("%s: %v", g, out)
		}
	}

	out, _ := e.call(t, "network_show", map[string]any{"device": "dev1", "command": "show snmp"})
	// the whole community table goes: over-redaction is accepted
	if fmt.Sprint(out["data"]) != "map[TABLE_snmp_community:<redacted> sys_contact:noc]" || out["_redactions"] != 1.0 {
		t.Errorf("JSON redaction: %v", out)
	}
	out, _ = e.call(t, "network_show", map[string]any{"device": "dev1", "command": "show system resources"})
	if tr, _ := out["_truncation"].(map[string]any); out["parsed"] != false || tr["reason"] != "bytes" || !strings.HasPrefix(fmt.Sprint(out["output"]), "{\n \"rows\"") {
		t.Errorf("JSON past 60 KiB: %.300v", out)
	}
	out, _ = e.call(t, "network_show", map[string]any{"device": "dev1", "command": "show clock", "include": []string{"simple_time"}})
	if out["parsed"] != false || out["output"] != ` "simple_time": "12:00:00"` {
		t.Errorf("filtered JSON: %v", out)
	}
	out, _ = e.call(t, "network_show", map[string]any{"device": "dev1", "command": "show uptime"})
	if out["parsed"] != true || fmt.Sprint(out["data"]) != "map[sys_up_days:1359]" {
		t.Errorf("JSON after leading noise: %v", out)
	}
	out, _ = e.call(t, "network_show", map[string]any{"device": "dev1", "command": "show hostname"})
	if out["parsed"] != false || out["output"] != "dev1" {
		t.Errorf("non-JSON reply: %v", out)
	}
	out, _ = e.call(t, "network_show", map[string]any{"device": "dev1", "command": "show bogus"})
	if !strings.Contains(fmt.Sprint(out["device_error"]), "% Invalid command") {
		t.Errorf("device error: %v", out)
	}

	// a user can never send the pipe; only the server appends it
	before := len(e.commands())
	for _, c := range []string{"show version | json", "show version |json", "show version json | json"} {
		if _, errText := e.call(t, "network_show", map[string]any{"device": "dev1", "command": c}); !strings.Contains(errText, "not allowed") {
			t.Errorf("%q: %s", c, errText)
		}
	}
	if len(e.commands()) != before {
		t.Fatal("a refused pipe reached the device")
	}
	for _, c := range e.commands() {
		if strings.HasPrefix(c, "show") && (!strings.HasSuffix(c, " | json") || strings.Count(c, "|") != 1) {
			t.Errorf("sent %q", c)
		}
	}
}

func TestGetterArgs(t *testing.T) {
	e := start(t, map[string]string{"show version": "x"}, sshfake.Options{})
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"device": "dev1", "getter": "facts"}, "available: none"},
		{map[string]any{"device": "dev1"}, "exactly one"},
		{map[string]any{"device": "dev1", "getter": "facts", "command": "show version"}, "exactly one"},
		{map[string]any{"device": "dev1", "getter": "nope"}, "getter"},
	} {
		if _, errText := e.call(t, "network_show", tc.args); !strings.Contains(errText, tc.want) {
			t.Errorf("%v: %q, want %q", tc.args, errText, tc.want)
		}
	}
	if got := e.commands(); len(got) != 0 {
		t.Fatalf("sent %q", got)
	}
	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if b, _ := json.Marshal(tl.InputSchema); tl.Name == "network_show" && !strings.Contains(string(b), `"enum":["arp_table","bgp_neighbors","cdp_neighbors"`) {
			t.Errorf("getter enum: %s", b)
		}
	}
}

// TestOwnCaptures replays sanitized captures from the team's own devices
// (testdata/own, recorded with cmd/record) through every getter they cover.
func TestOwnCaptures(t *testing.T) {
	for _, fam := range []struct{ profile, platform, suffix string }{{"iosxe", "cisco_iosxe", ""}, {"nxos", "cisco_nxos", " | json"}} {
		dir := filepath.Join("..", "..", "testdata", "own", fam.profile)
		ents := must(os.ReadDir(dir))
		cmds := map[string]string{"terminal width 512": "", "terminal width 511": "", "terminal length 0": ""}
		for _, ent := range ents {
			g := strings.TrimSuffix(ent.Name(), ".txt")
			cmds[platform.Profiles[fam.profile][g]+fam.suffix] = string(must(os.ReadFile(filepath.Join(dir, ent.Name()))))
		}
		e := startWith(t, setup{eng: &sshfake.Engine{Hostname: "dev1", Commands: cmds}, platform: fam.platform})
		for _, ent := range ents {
			g := strings.TrimSuffix(ent.Name(), ".txt")
			raw := cmds[platform.Profiles[fam.profile][g]+fam.suffix]
			out, errText := e.call(t, "network_show", map[string]any{"device": "dev1", "getter": g})
			if fam.suffix == "" {
				if errText != "" || out["parsed"] != false || out["output"] != text(raw) {
					t.Errorf("%s/%s: %.300v %s", fam.profile, g, out, errText)
				}
				continue
			}
			var want any
			if err := json.Unmarshal([]byte(raw), &want); err != nil {
				t.Fatalf("%s/%s: capture is not JSON: %v", fam.profile, g, err)
			}
			want, _ = output.RedactJSON(want)
			if errText != "" || out["parsed"] != true || !reflect.DeepEqual(out["data"], want) {
				t.Errorf("%s/%s: %.300v %s", fam.profile, g, out, errText)
			}
		}
	}
}
