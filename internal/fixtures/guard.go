// Package fixtures holds the public-repo guard: committed test data may hold
// only documentation addresses and names, and no secrets.
package fixtures

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// The patterns the guard scans for; cmd/sanitize rewrites the same matches.
var (
	IPv4   = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	IPv6   = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}`)
	MAC    = regexp.MustCompile(`(?i)\b[0-9a-f]{2}([:-][0-9a-f]{2}){5}\b|\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b`)
	FQDN   = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(com|net|org|edu|gov|mil|int|io|co|us|uk|de|info|biz|local|lan|corp|internal|home|arpa)\b`)
	Secret = regexp.MustCompile(`(?i)\b(password|secret|community|key-string|pre-shared-key|authentication-key|md5)\s+(\S+)`)

	docV4 = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("127.0.0.0/8"),
	}
	docV6 = netip.MustParsePrefix("2001:db8::/32")
)

// Violations lists every value in text that would expose a real environment.
func Violations(text string) []string {
	var out []string
	for _, m := range IPv4.FindAllString(text, -1) {
		if a, err := netip.ParseAddr(m); err == nil && !okV4(a) {
			out = append(out, "IPv4 "+m)
		}
	}
	for _, m := range IPv6.FindAllString(text, -1) {
		if a, err := netip.ParseAddr(m); err == nil && a.Is6() && !docV6.Contains(a) && !a.IsLoopback() && !a.IsUnspecified() {
			out = append(out, "IPv6 "+m)
		}
	}
	for _, m := range MAC.FindAllString(text, -1) {
		h := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(m))
		if !strings.HasPrefix(h, "00005e0053") && h != "ffffffffffff" && h != "000000000000" {
			out = append(out, "MAC "+m)
		}
	}
	for _, m := range FQDN.FindAllString(text, -1) {
		l := strings.ToLower(m)
		if l != "example.com" && l != "example.net" && l != "example.org" &&
			!strings.HasSuffix(l, ".example.com") && !strings.HasSuffix(l, ".example.net") && !strings.HasSuffix(l, ".example.org") {
			out = append(out, "FQDN "+m)
		}
	}
	for _, m := range Secret.FindAllStringSubmatch(text, -1) {
		if v := m[2]; !(strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">")) {
			out = append(out, fmt.Sprintf("secret line %q", m[0]))
		}
	}
	return out
}

// okV4 allows documentation and loopback addresses, plus netmasks and
// wildcard masks, which are not addresses.
func okV4(a netip.Addr) bool {
	for _, p := range docV4 {
		if p.Contains(a) {
			return true
		}
	}
	b := a.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return n&(n+1) == 0 || ^n&(^n+1) == 0 // wildcard 0..01..1 or mask 1..10..0
}
