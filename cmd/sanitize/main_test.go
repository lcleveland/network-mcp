package main

import (
	"testing"

	"github.com/lcleveland/network-mcp/internal/fixtures"
)

func TestRules(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ip address 10.1.2.3 255.255.255.0", "ip address 192.0.2.1 255.255.255.0"},
		{"10.0.0.1 10.0.0.2 10.0.0.1", "192.0.2.1 192.0.2.2 192.0.2.1"},
		{"to 10.0.0.1 via 192.0.2.1", "to 192.0.2.2 via 192.0.2.1"},
		{"ipv6 address fd00::1/64, FD00::1", "ipv6 address 2001:db8::1/64, 2001:db8::1"},
		{"3c:22:fb:01:02:03 a4b1.c2d3.e4f5 3C-22-FB-01-02-03", "00:00:5e:00:53:00 0000.5e00.5301 00-00-5e-00-53-00"},
		{"ip domain name acme.local\nntp server ntp.acme.local", "ip domain name name1.example.com\nntp server name2.example.com"},
		{"core1 uptime is 3 days\ncore1#show clock", "dev1 uptime is 1 week, 2 days, 3 hours, 4 minutes\ndev1#show clock"},
		{"hostname sw-a\nsw-a(config)#end\nsw-b>", "hostname dev1\ndev1(config)#end\ndev2>"},
		{"username alice privilege 15", "username user1 privilege 15"},
		{"Processor board ID FOC1234X0AB\nSN: FOC1234X0AB", "Processor board ID SERIAL1\nSN: SERIAL1"},
		{"cisco WS-C3850-48P (MIPS) processor", "cisco MODEL1 (MODEL2) processor"},
		{"IOS XE Software (X86-UNIVERSALK9-M), Version 16.9.3\nip ssh version 2", "IOS XE Software (fw2), Version fw1\nip ssh version 2"},
		{"Last login: Mon Jan 1 from 10.9.9.9\nok", "ok"},
		{"Compiled Thu 27-Jan-11 12:07 by x\nok", "ok"},
		{"enable secret 5 $1$abcd\nok", "ok"},
		{"banner motd ^C\nhello\n^C\nok", "ok"},
		{"snmp-server community <removed> RO", "snmp-server community <removed> RO"},
	}
	for _, c := range cases {
		got := sanitize(c.in)
		if got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
		if again := sanitize(got); again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
}

func TestPlantedFixture(t *testing.T) {
	raw := `Last login: Tue Mar 3 10:01:02 2026 from 10.20.30.40
core-sw1.corp.acme.com uptime is 4 weeks
hostname core-sw1
ip domain name corp.acme.com
username netops privilege 15 secret 9 $9$abcdefgh
interface Vlan10
 ip address 172.16.5.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 192.168.1.254
core-sw1#
`
	if len(fixtures.Violations(raw)) == 0 {
		t.Fatal("planted fixture passed the guard before sanitizing")
	}
	got := sanitize(raw)
	if v := fixtures.Violations(got); len(v) != 0 {
		t.Fatalf("%v\n%s", v, got)
	}
	if sanitize(raw) != got || sanitize(got) != got {
		t.Fatal("not deterministic or not idempotent")
	}
}
