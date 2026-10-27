package deny

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func check(t *testing.T, l List, d Derived, line string) error {
	t.Helper()
	_, err := l.Check([]string{line}, d)
	return err
}

func TestDefaultEntries(t *testing.T) {
	l, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range slices.Concat(Default, mode) {
		for _, line := range []string{e, e + " x", "no " + e + " x", "default " + e, strings.ToUpper(e) + " x"} {
			if check(t, l, Derived{}, line) == nil {
				t.Errorf("%q not denied", line)
			}
		}
	}
}

func TestDenied(t *testing.T) {
	l, _ := New(nil)
	for _, line := range []string{
		"userna x", "cryp key generate rsa", "no logg", "no logging host 192.0.2.9", "default logging buffered",
		"defa userna x", "n userna x", "no no username x", "  username   x  privilege 15",
		"ip h access-class 5", "ip ht server", "i ss version 2", "ip sc server enable", "ip tf blocksize 8192",
		"ena secret x", "li vty 0 4", "snmp community x", "sn community x", "event man applet x", "conf mode excl",
		"serv int", "radius server x", "radius-ser host 192.0.2.1", "rollb running-config checkpoint x", "feat bash",
		"do show run", "d show run", "end", "en", "exit", "ex", "conf t", "configure terminal", "CONFIGURE TERMINAL",
		"banner motd ^C", "key chain x", "boot system flash:x", "rel", "aaa new-model", "tac", "privilege exec level 1 show",
		// syntax
		"description a\tb", "description a?", "show version | include x", "description a\r", "description a\nusername x",
		"description café", "", "   ",
	} {
		if check(t, l, Derived{}, line) == nil {
			t.Errorf("%q not denied", line)
		}
	}
}

func TestAllowed(t *testing.T) {
	l, _ := New(nil)
	lines := []string{
		"interface GigabitEthernet1/0/2", " description uplink to core", " switchport access vlan 10", " no shutdown",
		"vlan 10", " name users", "router bgp 64496", " address-family ipv4", " neighbor 192.0.2.2 activate",
		" exit-address-family", "ip route 198.51.100.0 255.255.255.0 192.0.2.1", "spanning-tree portfast default",
		"ip access-list extended USERS", " permit ip any any", "default interface GigabitEthernet1/0/3", "ip sla 1",
		"service timestamps log datetime msec", "ip domain name example.net", "ntp server 192.0.2.123",
	}
	got, err := l.Check(lines, Derived{})
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != "description uplink to core" {
		t.Errorf("normalized %q", got[1])
	}
}

func TestWholePlan(t *testing.T) {
	l, _ := New(nil)
	if _, err := l.Check([]string{"vlan 10", " name users", "username x secret y", "vlan 20"}, Derived{}); err == nil ||
		!strings.Contains(err.Error(), "line 3") || strings.Contains(err.Error(), "secret y") {
		t.Fatalf("one denied line must refuse the plan without echoing it: %v", err)
	}
	ok := slices.Repeat([]string{"vlan 10"}, MaxLines)
	if _, err := l.Check(ok, Derived{}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Check(append(ok, "vlan 11"), Derived{}); err == nil {
		t.Fatal("more than MaxLines accepted")
	}
	if _, err := l.Check(nil, Derived{}); err == nil {
		t.Fatal("empty plan accepted")
	}
}

func TestWriteDeny(t *testing.T) {
	l, err := New([]string{"spanning-tree", "ip route"})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"span portfast default", "ip ro 0.0.0.0 0.0.0.0 192.0.2.1", "username x"} {
		if check(t, l, Derived{}, line) == nil {
			t.Errorf("%q not denied", line)
		}
	}
	// there is no way to remove an entry: these only add
	l, _ = New([]string{"no username", "!username", "-username"})
	if check(t, l, Derived{}, "username x") == nil {
		t.Error("write_deny shrank the compiled-in list")
	}
	for _, bad := range []string{"", " ", "a\tb", "a?", "a|b", "a\nb"} {
		if _, err := New([]string{bad}); err == nil {
			t.Errorf("write_deny %q accepted", bad)
		}
	}
}

const iosRun = `Building configuration...
hostname sw1
!
vrf definition Mgmt-intf
 address-family ipv4
 exit-address-family
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-intf
 ip address 192.0.2.10 255.255.255.0
 ip access-group MGMT-IN in
 negotiation auto
!
interface GigabitEthernet1/0/1
 switchport access vlan 10
!
interface Vlan10
 ip address 198.51.100.1 255.255.255.0
 ipv6 address 2001:DB8::10/64
!
ip access-list standard VTY-ACL
 permit 192.0.2.0 0.0.0.255
ip route vrf Mgmt-intf 0.0.0.0 0.0.0.0 192.0.2.1
ip http access-class ipv4 HTTP-ACL
snmp-server community fakecomm RO 99
snmp-server user u1 g1 v3 auth sha fakepass priv aes 128 fakepriv access SNMP-V3
line vty 0 4
 access-class VTY-ACL in vrf-also
`

const nxosRun = `!Command: show running-config
vrf context management
  ip route 0.0.0.0/0 192.0.2.1
interface mgmt0
  vrf member management
  ip address 192.0.2.20/24
interface Ethernet1/1
  description x
snmp-server community fakecomm group network-operator
snmp-server community fakecomm use-acl SNMP-ACL
line vty
  access-class VTY4 in
`

func TestDerive(t *testing.T) {
	l, _ := New(nil)
	for _, tc := range []struct {
		run             string
		connect         string
		want            string
		denied, allowed []string
	}{
		{iosRun, "192.0.2.10", "{[http-acl 99 snmp-v3 vty-acl mgmt-in] [mgmt-intf mgmt-intf] [gigabitethernet0/0]}",
			[]string{
				"ip access-list standard VTY-ACL", "ip access-list ext http-acl", "access-list 99 permit any",
				"no ip access-list standard mgmt-in", "ip acc resequence SNMP-V3 10 10", "vrf definition Mgmt-intf",
				"ip route vrf Mgmt-intf 0.0.0.0 0.0.0.0 192.0.2.254", "interface GigabitEthernet0/0", "int gi0/0",
				"int Gi 0/0", "interface gi0/0.100", "interface range gi0/0 - 1", "default interface gi0/0",
				"interface range gi1/0/1 - 2, gi0/0", "interface range g0/0-0/2",
			},
			[]string{
				"interface gi1/0/1", "interface range gi1/0/1 - 4", "ip access-list standard USERS", "access-list 98 permit any",
				"ip route 0.0.0.0 0.0.0.0 198.51.100.254", "interface Vlan10", "ip access-list standard fakecomm",
				"ip access-list standard fakepass", "interface range gi0/1 - 4",
			}},
		{iosRun, "2001:db8::10", "{[http-acl 99 snmp-v3 vty-acl] [mgmt-intf] [vlan10]}",
			[]string{"interface vlan 10", "int vl10"}, []string{"interface gi0/0", "interface vlan 100"}},
		{nxosRun, "192.0.2.20", "{[network-operator snmp-acl vty4] [management management] [mgmt0]}",
			[]string{"interface mgmt0", "int mgmt 0", "vrf context management", "ip access-list SNMP-ACL",
				"interface ethernet1/1-4, mgmt0", "no ip access-list vty4"},
			[]string{"interface ethernet1/1-4", "ip access-list USERS"}},
	} {
		d := Derive(tc.run, netip.MustParseAddr(tc.connect))
		if got := fmt.Sprint(d); got != tc.want {
			t.Errorf("%s: derived %s, want %s", tc.connect, got, tc.want)
		}
		for _, line := range tc.denied {
			if check(t, l, d, line) == nil {
				t.Errorf("%s: %q not denied", tc.connect, line)
			}
		}
		for _, line := range tc.allowed {
			if err := check(t, l, d, line); err != nil {
				t.Errorf("%s: %q denied: %v", tc.connect, line, err)
			}
		}
	}
}
