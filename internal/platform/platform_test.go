package platform

import (
	"slices"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/gate"
)

func TestResolve(t *testing.T) {
	for value, want := range map[string][2]string{
		"ios-xe": {IOSXE, "iosxe"}, "IOSXE": {IOSXE, "iosxe"}, "cisco_iosxe": {IOSXE, "iosxe"}, "Cisco-IOS-XE": {IOSXE, "iosxe"},
		"nx-os": {NXOS, "nxos"}, "NXOS": {NXOS, "nxos"}, "cisco_nxos": {NXOS, "nxos"}, "cisco-nx-os": {NXOS, "nxos"},
		"ios": {Generic, "ios"}, "cisco_ios": {Generic, "ios"}, "CISCO-IOS": {Generic, "ios"},
		"": {Generic, ""}, "junos": {Generic, ""}, "c9k": {Generic, ""},
	} {
		if d := Resolve(value, nil); d.Driver != want[0] || d.Profile != want[1] {
			t.Errorf("%q: %s/%s, want %v", value, d.Driver, d.Profile, want)
		}
	}
	if d := Resolve("ios", nil); d.Getters["environment"] != "show environment" || d.Getters["facts"] != "show version" {
		t.Errorf("ios getters: %v", d.Getters)
	}
	if d := Resolve("nxos", nil); d.Getters["routes"] != "show ip route vrf all" || len(d.Getters) != 12 {
		t.Errorf("nxos getters: %v", d.Getters)
	}
	if d := Resolve("junos", nil); len(d.Getters) != 0 {
		t.Errorf("generic has getters: %v", d.Getters)
	}

	cfg := map[string]Config{
		"C9K":   {Driver: IOSXE, Profile: "iosxe", ReadAllow: []string{"who"}},
		"aos":   {Getters: map[string]string{"facts": "show version", "clients": "show clients"}},
		"nx-os": {Driver: Generic},
	}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	if d := Resolve("c9k", cfg); d.Driver != IOSXE || d.Profile != "iosxe" || !slices.Equal(d.Gate.Allow, []string{"who"}) {
		t.Errorf("explicit driver: %+v", d)
	}
	if d := Resolve("aos", cfg); d.Driver != Generic || len(d.Getters) != 2 || d.Getters["clients"] != "show clients" {
		t.Errorf("configured getters: %+v", d)
	}
	if d := Resolve("NX-OS", cfg); d.Driver != Generic || d.Profile != "nxos" {
		t.Errorf("override keeps the profile: %+v", d)
	}
	if Resolve("ios", nil).Config != cisco || Resolve("NX-OS", cfg).Config != cisco || Resolve("junos", nil).Config != (ConfigCmds{}) {
		t.Error("compiled-in config commands")
	}
	aos := map[string]Config{"aos": {Config: ConfigCmds{Running: "show config running"}}}
	if d := Resolve("AOS", aos); d.Config != aos["aos"].Config || Validate(aos) != nil {
		t.Errorf("configured config commands: %+v", d.Config)
	}
	aos["aos"] = Config{Config: ConfigCmds{Startup: "show config | include x"}}
	if err := Validate(aos); err == nil || !strings.Contains(err.Error(), "platforms.aos.config.startup") {
		t.Errorf("config command with a pipe: %v", err)
	}
	if n := GetterNames(cfg); !slices.Contains(n, "clients") || !slices.Contains(n, "bgp_neighbors") || len(n) != 13 {
		t.Errorf("names: %v", n)
	}
}

// Every compiled-in getter command passes the read gate.
func TestGettersPassGate(t *testing.T) {
	for p, m := range Profiles {
		for name, cmd := range m {
			if got, err := gate.Check(cmd, gate.Ext{}); err != nil || got != cmd {
				t.Errorf("%s.%s %q: %v", p, name, cmd, err)
			}
		}
	}
}

func TestRevert(t *testing.T) {
	if err := Validate(map[string]Config{"cisco_iosxe": {Revert: RevertServer}, "c9k": {Driver: IOSXE, Revert: RevertDevice}}); err != nil {
		t.Fatal(err)
	}
	if d := Resolve("CISCO_IOSXE", map[string]Config{"cisco_iosxe": {Revert: RevertServer}}); d.Driver != IOSXE || d.Revert != RevertServer {
		t.Fatalf("%+v", d)
	}
	for _, bad := range []map[string]Config{
		{"cisco_iosxe": {Revert: "timer"}},
		{"cisco_nxos": {Revert: RevertServer}},
		{"cisco_iosxe": {Driver: NXOS, Revert: RevertServer}},
		{"weird": {Revert: RevertServer}},
	} {
		if err := Validate(bad); err == nil || !strings.Contains(err.Error(), "revert") {
			t.Errorf("%v: %v", bad, err)
		}
	}
}
