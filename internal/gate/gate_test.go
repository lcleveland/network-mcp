package gate

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	allowed := map[string]string{
		"show version":                   "show version",
		"  SHOW   ip  route ":            "SHOW ip route",
		"display interface brief":        "display interface brief",
		"dir flash:":                     "dir flash:",
		"ping 192.0.2.1":                 "ping 192.0.2.1",
		"ping vrf mgmt 192.0.2.1 source": "ping vrf mgmt 192.0.2.1 source",
		"traceroute 2001:db8::1":         "traceroute 2001:db8::1",
		"show interfaces Gi1/0/1":        "show interfaces Gi1/0/1",
		"show controllers":               "show controllers",
		"show arp":                       "show arp",
	}
	for in, want := range allowed {
		got, err := Check(in)
		if err != nil || got != want {
			t.Errorf("Check(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	refused := map[string]string{
		"":                                 "empty",
		"show version | include x":         "character",
		"show version; reload":             "character",
		"show version\nreload":             "character",
		"show ?":                           "character",
		"show \"x\"":                       "character",
		"show vérsion":                     "character",
		"show " + strings.Repeat("x", 300): "256",
		"sh version":                       "abbreviation",
		"SH ip route":                      "abbreviation",
		"write memory":                     "allowed",
		"ping":                             "target",
		"ping 192.0.2.1 repeat 1000":       "ping",
		"ping 192.0.2.1 rep 1000":          "ping",
		"traceroute 192.0.2.1 timeout 1":   "traceroute",
		"ping a b c d e f":                 "6",
	}
	for _, d := range Deny {
		refused[d] = "denied"
		refused[abbreviate(d)] = "denied"
	}
	for _, s := range []string{"deb all", "sh run", "conf t", "show running-config", "show startup-config", "show tech-support", "term len 0", "show file systems"} {
		refused[s] = "denied"
	}
	for in, msg := range refused {
		if _, err := Check(in); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("Check(%q) = %v; want error containing %q", in, err, msg)
		}
	}
}

// abbreviate cuts every token to its first three letters, as an operator would.
func abbreviate(s string) string {
	f := strings.Fields(s)
	for i, w := range f {
		f[i] = w[:min(3, len(w))]
	}
	return strings.Join(f, " ")
}
