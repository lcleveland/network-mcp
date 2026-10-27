// Package platform maps a device's platform value to a driver and a getter
// profile, and holds the NAPALM-named getters (#9 §2): raw output, no parsers.
package platform

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/lcleveland/network-mcp/internal/gate"
)

// Drivers.
const (
	IOSXE   = "iosxe"
	NXOS    = "nxos"
	Generic = "generic_ssh"
)

// Config is one platforms.<value> entry of the config file. It may map a
// site's own platform value to a driver and profile; nothing is inferred.
type Config struct {
	Driver    string            `yaml:"driver"`
	Profile   string            `yaml:"profile"`
	Getters   map[string]string `yaml:"getters"` // name -> command, over the profile's
	ReadAllow []string          `yaml:"read_allow"`
	ReadDeny  []string          `yaml:"read_deny"`
	Config    ConfigCmds        `yaml:"config"` // over the profile's
	// Revert is how an IOS-XE change is undone: device (the default, the
	// device's archive revert timer) or server (a flash snapshot the server
	// restores, for devices without archive path).
	Revert string `yaml:"revert"`
}

// Revert modes.
const (
	RevertDevice = "device"
	RevertServer = "server"
)

// ConfigCmds are what network_config sends. They skip the read gate's deny
// list, which blocks config dumps on purpose, but not its character set.
type ConfigCmds struct {
	Running string `yaml:"running"`
	Startup string `yaml:"startup"`
}

// cisco is the config command pair of every compiled-in profile.
var cisco = ConfigCmds{"show running-config", "show startup-config"}

// aliases are the compiled-in platform values (lower case): driver, profile.
var aliases = map[string][2]string{
	"ios-xe": {IOSXE, "iosxe"}, "iosxe": {IOSXE, "iosxe"}, "cisco_iosxe": {IOSXE, "iosxe"}, "cisco-ios-xe": {IOSXE, "iosxe"},
	"nx-os": {NXOS, "nxos"}, "nxos": {NXOS, "nxos"}, "cisco_nxos": {NXOS, "nxos"}, "cisco-nx-os": {NXOS, "nxos"},
	"ios": {Generic, "ios"}, "cisco_ios": {Generic, "ios"}, "cisco-ios": {Generic, "ios"},
}

var iosxe = map[string]string{
	"facts":             "show version",
	"inventory":         "show inventory",
	"environment":       "show environment all",
	"interfaces":        "show interfaces",
	"interfaces_ip":     "show ip interface",
	"vlans":             "show vlan brief",
	"lldp_neighbors":    "show lldp neighbors detail",
	"cdp_neighbors":     "show cdp neighbors detail",
	"arp_table":         "show ip arp",
	"mac_address_table": "show mac address-table",
	"routes":            "show ip route",
	"bgp_neighbors":     "show ip bgp summary",
}

// Profiles are the compiled-in getter tables.
var Profiles = map[string]map[string]string{
	"iosxe": iosxe,
	"ios":   with(iosxe, "environment", "show environment"),
	"nxos": with(iosxe,
		"interfaces", "show interface",
		"interfaces_ip", "show ip interface vrf all",
		"environment", "show environment",
		"arp_table", "show ip arp vrf all",
		"routes", "show ip route vrf all",
		"bgp_neighbors", "show bgp all summary"),
}

func with(m map[string]string, kv ...string) map[string]string {
	m = maps.Clone(m)
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// Device is what a platform value resolves to.
type Device struct {
	Driver, Profile string
	Revert          string // "" means the driver's default
	Getters         map[string]string
	Gate            gate.Ext
	Config          ConfigCmds
}

// Resolve maps a platform value, case-insensitively. Unknown or missing
// values get the generic driver and no getters.
func Resolve(value string, cfg map[string]Config) Device {
	a, ok := aliases[strings.ToLower(value)]
	if !ok {
		a = [2]string{Generic, ""}
	}
	d := Device{Driver: a[0], Profile: a[1]}
	var extra map[string]string
	var cc ConfigCmds
	for k, c := range cfg {
		if strings.EqualFold(k, value) {
			d.Driver, d.Profile, d.Revert = cmp.Or(c.Driver, d.Driver), cmp.Or(c.Profile, d.Profile), c.Revert
			d.Gate, extra, cc = gate.Ext{Allow: c.ReadAllow, Deny: c.ReadDeny}, c.Getters, c.Config
		}
	}
	if d.Profile != "" {
		d.Config = cisco
	}
	d.Config = ConfigCmds{cmp.Or(cc.Running, d.Config.Running), cmp.Or(cc.Startup, d.Config.Startup)}
	d.Getters = map[string]string{}
	maps.Copy(d.Getters, Profiles[d.Profile])
	maps.Copy(d.Getters, extra)
	return d
}

// Validate refuses startup on an unknown driver or profile, a key that
// repeats ignoring case, a getter command the platform's read gate refuses,
// or a config command outside the gate's character set.
func Validate(cfg map[string]Config) error {
	seen := map[string]bool{}
	for k, c := range cfg {
		l := strings.ToLower(k)
		switch _, ok := Profiles[c.Profile]; {
		case l == "" || seen[l]:
			return fmt.Errorf("platforms: %q is empty or repeats ignoring case", k)
		case c.Driver != "" && !slices.Contains([]string{IOSXE, NXOS, Generic}, c.Driver):
			return fmt.Errorf("platforms.%s.driver: unknown %q (want %s, %s or %s)", k, c.Driver, IOSXE, NXOS, Generic)
		case c.Profile != "" && !ok:
			return fmt.Errorf("platforms.%s.profile: unknown %q (want %s)", k, c.Profile, strings.Join(slices.Sorted(maps.Keys(Profiles)), ", "))
		case c.Revert != "" && c.Revert != RevertDevice && c.Revert != RevertServer:
			return fmt.Errorf("platforms.%s.revert: unknown %q (want %s or %s)", k, c.Revert, RevertDevice, RevertServer)
		case c.Revert == RevertServer && cmp.Or(c.Driver, Resolve(k, nil).Driver) != IOSXE:
			return fmt.Errorf("platforms.%s.revert: server is for IOS-XE only (NX-OS is always server-reverted)", k)
		}
		seen[l] = true
		x := gate.Ext{Allow: c.ReadAllow, Deny: c.ReadDeny}
		if err := x.Validate(); err != nil {
			return fmt.Errorf("platforms.%s: %w", k, err)
		}
		for src, cmd := range map[string]string{"running": c.Config.Running, "startup": c.Config.Startup} {
			if err := gate.Chars(cmd); err != nil {
				return fmt.Errorf("platforms.%s.config.%s: %w", k, src, err)
			}
		}
		for name, cmd := range c.Getters {
			if name == "" {
				return fmt.Errorf("platforms.%s.getters: empty name", k)
			}
			if _, err := gate.Check(cmd, x); err != nil {
				return fmt.Errorf("platforms.%s.getters.%s: %w", k, name, err)
			}
		}
	}
	return nil
}

// GetterNames lists every getter name, compiled in or configured, sorted.
func GetterNames(cfg map[string]Config) []string {
	var names []string
	for _, m := range Profiles {
		names = slices.AppendSeq(names, maps.Keys(m))
	}
	for _, c := range cfg {
		names = slices.AppendSeq(names, maps.Keys(c.Getters))
	}
	slices.Sort(names)
	return slices.Compact(names)
}
