package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"ansi csi", "a\x1b[1;31mred\x1b[0m b", "ared b"},
		{"ansi osc bel", "a\x1b]0;title\x07b", "ab"},
		{"ansi osc st", "a\x1b]8;;http://x.example.com\x1b\\b", "ab"},
		{"c0", "a\x00b\x07c\x08d", "abcd"},
		{"tab and newline kept", "a\tb\nc", "a\tb\nc"},
		{"crlf", "a\r\nb\rc", "a\nb\nc"},
		{"del and c1", "a\x7fb\u0085c\u009bd", "abcd"},
		{"bidi", "a\u202ab\u202ec\u2066d\u2069e", "abcde"},
		{"zero width", "a\u200bb\u200fc\ufeffd", "abcd"},
		{"tags", "a\U000e0001b\U000e007fc", "abc"},
		{"invalid utf-8", "a\xffb", "a\ufffdb"},
		{"printable unicode kept", "Gi1/0/1 – é", "Gi1/0/1 – é"},
	} {
		if got := Sanitize(c.in); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRedact(t *testing.T) {
	const R = Redacted
	for _, c := range []struct{ in, want string }{
		// Oxidized ios.rb / nxos.rb and NAPALM CISCO_SANITIZE_FILTERS
		{"snmp-server community public RO", "snmp-server community " + R},
		{"snmp-server host 192.0.2.1 version 2c public", "snmp-server host 192.0.2.1 version 2c " + R},
		{"snmp-server host 192.0.2.1 informs version 3 priv snmpuser", "snmp-server host 192.0.2.1 informs version 3 priv " + R},
		{"snmp-server host 192.0.2.1 traps version 2c public udp-port 162", "snmp-server host 192.0.2.1 traps version 2c " + R + " udp-port 162"},
		{"snmp-server user u1 g1 v3 auth sha authpass1 priv aes 128 privpass1", "snmp-server user u1 g1 v3 auth sha " + R + " priv aes 128 " + R},
		{"snmp-server user u1 network-admin auth md5 0xabc priv 0xdef localizedkey", "snmp-server user u1 network-admin auth md5 " + R + " priv " + R + " localizedkey"},
		{"snmp-server mib community-map public context c1", "snmp-server mib community-map " + R + " context c1"},
		{"username admin privilege 15 secret 9 $9$abc$def", "username admin privilege 15 secret 9 " + R},
		{"username admin password 5 $1$abc$def role network-admin", "username admin password 5 " + R},
		{"enable secret 5 $1$abc$def", "enable secret 5 " + R},
		{"enable password level 15 7 0822455D0A16", "enable password level 15 7 " + R},
		{" password 7 0822455D0A16", " password 7 " + R},
		{" secret fakesecret", " secret " + R},
		{" aaa root secret 5 $1$abc", " aaa root secret 5 " + R},
		{" wpa-psk ascii 0 fakepassphrase", " wpa-psk ascii 0 " + R},
		{" ip authentication key 7 0822455D0A16", " ip authentication key 7 " + R},
		{"tacacs-server host 192.0.2.5 key 7 0822455D0A16", "tacacs-server host 192.0.2.5 key 7 " + R},
		{"tacacs-server key fakekey", "tacacs-server key " + R},
		{"radius-server key 7 0822455D0A16", "radius-server key 7 " + R},
		{" key 7 0822455D0A16", " key 7 " + R},
		{" key fakekey", " key " + R},
		{"crypto isakmp key fakepsk address 192.0.2.9", "crypto isakmp key " + R + " address 192.0.2.9"},
		{" ip ospf message-digest-key 1 md5 fakekey", " ip ospf message-digest-key 1 md5 " + R},
		{" ip ospf authentication-key fakekey", " ip ospf authentication-key " + R},
		{" neighbor 192.0.2.2 password fakepass", " neighbor 192.0.2.2 password " + R},
		{" vrrp 1 authentication text fakepw", " vrrp 1 authentication text " + R},
		{" standby 1 authentication fakepw", " standby 1 authentication " + R},
		{" standby 1 authentication md5 key-string fakekey timeout 30", " standby 1 authentication md5 key-string " + R + " timeout 30"},
		{" key-string fakekey", " key-string " + R},
		{" ppp chap password 7 0822455D0A16", " ppp chap password 7 " + R},
		{" security wpa psk set-key ascii 0 fakepsk", " security wpa psk set-key ascii 0 " + R},
		{" dot1x username u1 password 0 fakepw", " dot1x username u1 password 0 " + R},
		{" mgmtuser username u1 password 0 fakepw secret 0 fakesecret", " mgmtuser username u1 password 0 " + R + " secret 0 " + R},
		{" client 192.0.2.3 server-key 7 0822455D0A16", " client 192.0.2.3 server-key 7 " + R},
		{" domain-password fakepw authenticate snp", " domain-password " + R + " authenticate snp"},
		{" pre-shared-key fakepsk", " pre-shared-key " + R},
		{"hash $8$abc$def in text", "hash " + R + " in text"},
		// catch-all, case-insensitive; over-redaction is accepted
		{"Community: fakecomm", "Community: fakecomm"},
		{"wifi PSK fakepsk", "wifi PSK " + R},
		{"passphrase 3 fakephrase", "passphrase 3 " + R},
		{"monkey business", "monkey " + R},
		// untouched
		{"service password-encryption", "service password-encryption"},
		{"GigabitEthernet1 is up, line protocol is up", "GigabitEthernet1 is up, line protocol is up"},
		{"key", "key"},
	} {
		got, n := Redact(c.in)
		if got != c.want {
			t.Errorf("%q\n got %q\nwant %q", c.in, got, c.want)
		}
		if want := strings.Count(c.want, R); n != want {
			t.Errorf("%q: %d redactions, want %d", c.in, n, want)
		}
	}
}

func TestRedactPrivateKey(t *testing.T) {
	in := "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\nAAAAfake\n-----END RSA PRIVATE KEY-----\nb\n-----BEGIN PRIVATE KEY-----\nMIIEcut"
	got, n := Redact(in)
	if got != "a\n-----BEGIN RSA PRIVATE KEY----- "+Redacted+"\nb\n-----BEGIN PRIVATE KEY----- "+Redacted || n != 2 {
		t.Fatalf("%q %d", got, n)
	}
}

func TestRedactAfterSanitize(t *testing.T) {
	got, n := Field("username u1 pass\x1b[0mword fakepw", FieldCap)
	if got != "username u1 password "+Redacted || n != 1 {
		t.Fatalf("%q %d", got, n)
	}
}

func TestRedactJSON(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{"name":"dev1","PSK":"a","api_key":"b","key":"c","keyboard":"ok",
		"nested":{"snmpCommunity":["x"],"list":[{"Password":"d"},{"line":"enable secret 5 $1$x"}]},
		"privateKey":{"pem":"e"},"n":1}`), &v)
	v, n := RedactJSON(v)
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	want := `{"PSK":"<redacted>","api_key":"<redacted>","key":"<redacted>","keyboard":"ok","n":1,"name":"dev1",` +
		`"nested":{"list":[{"Password":"<redacted>"},{"line":"enable secret 5 <redacted>"}],"snmpCommunity":"<redacted>"},"privateKey":"<redacted>"}` + "\n"
	if b.String() != want || n != 7 {
		t.Fatalf("%s %d", b.String(), n)
	}
}

func TestCap(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
	}{
		{"abc", 3, "abc"},
		{"abcdef", 3, "abc…[+3]"},
		{"ééééé", 2, "éé…[+3]"},
		{"", 0, ""},
	} {
		if got := Cap(c.in, c.max); got != c.want {
			t.Errorf("Cap(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
	long := strings.Repeat("x", 600)
	if got, _ := Field(long, FieldCap); got != long[:256]+"…[+344]" {
		t.Errorf("field cap: %q", got)
	}
	if got, _ := Field(long, LongCap); got != long[:512]+"…[+88]" {
		t.Errorf("device_error cap: %q", got)
	}
}

func TestFilter(t *testing.T) {
	cfg := "hostname dev1\ninterface Gi1\n description up\n shutdown\ninterface Gi2\n description down\nrouter ospf 1\n network 192.0.2.0 0.0.0.255 area 0\nend"
	for _, c := range []struct {
		name             string
		include, exclude []string
		section          string
		want             string
	}{
		{"none", nil, nil, "", cfg},
		{"include any", []string{"^interface", "ospf"}, nil, "", "interface Gi1\ninterface Gi2\nrouter ospf 1"},
		{"exclude", nil, []string{"^ "}, "", "hostname dev1\ninterface Gi1\ninterface Gi2\nrouter ospf 1\nend"},
		{"section", nil, nil, "^interface", "interface Gi1\n description up\n shutdown\ninterface Gi2\n description down"},
		{"section then include then exclude", []string{"description|Gi"}, []string{"down"}, "^interface", "interface Gi1\n description up\ninterface Gi2"},
		{"section no match", nil, nil, "^vlan", ""},
	} {
		f, err := NewFilter(c.include, c.exclude, c.section)
		if err != nil {
			t.Fatal(err)
		}
		if got, _, _ := f.Text(cfg, false); got != c.want {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
	nine := strings.Split("a b c d e f g h i", " ")
	for _, c := range []struct {
		name             string
		include, exclude []string
		section, want    string
	}{
		{"too many include", nine, nil, "", "include: at most 8"},
		{"too many exclude", nil, nine, "", "exclude: at most 8"},
		{"too long", []string{strings.Repeat("a", 257)}, nil, "", "longer than 256"},
		{"invalid", nil, []string{"(a"}, "", `exclude: invalid RE2 pattern "(a"`},
		{"no lookahead", []string{"a(?=b)"}, nil, "", "invalid RE2"},
		{"bad section", nil, nil, "[", "section: invalid RE2"},
	} {
		if _, err := NewFilter(c.include, c.exclude, c.section); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := NewFilter(nine[:8], nine[:8], strings.Repeat("a", 256)); err != nil {
		t.Errorf("limits are inclusive: %v", err)
	}
}

// bigText is a show interfaces-like output well over the result budget.
func bigText(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "GigabitEthernet1/0/%d is up, line protocol is up\n  Hardware is Gigabit Ethernet, address is 0000.5e00.5301\n  MTU 1500 bytes, BW 1000000 Kbit/sec\n", i)
	}
	return b.String()
}

func TestTextCuts(t *testing.T) {
	raw := bigText(2000) + "router bgp 64496\n neighbor 192.0.2.2 password fakepw\n"
	out, n, tr := (*Filter)(nil).Text(raw, false)
	if b, _ := json.Marshal(out); len(b) > MaxResult-envelope || tr == nil || tr.Reason != "bytes" || tr.Hint != HintCLI ||
		tr.Total != strings.Count(raw, "\n")+1 || tr.Shown != strings.Count(out, "\n")+1 || n != 1 {
		t.Fatalf("%d bytes, %+v, %d", len(b), tr, n)
	}
	f, _ := NewFilter(nil, nil, "^router bgp")
	if out, _, tr = f.Text(raw, false); out != "router bgp 64496\n neighbor 192.0.2.2 password "+Redacted || tr != nil {
		t.Fatalf("section past the cut: %q %+v", out, tr)
	}
	if _, _, tr = (*Filter)(nil).Text("x", true); tr == nil || tr.Reason != "device_limit" || tr.Shown != 1 {
		t.Fatalf("device limit: %+v", tr)
	}
}

func TestRedactBeforeCut(t *testing.T) {
	line := strings.Repeat("x", LineCap-10) + " password fakesecretvalue"
	out, n, _ := (*Filter)(nil).Text(line, false)
	if strings.Contains(out, "fake") || n != 1 || !strings.HasSuffix(out, "…[+"+fmt.Sprint(len([]rune(strings.Repeat("x", LineCap-10)+" password "+Redacted))-LineCap)+"]") {
		t.Fatalf("%q", out[LineCap-20:])
	}
}
