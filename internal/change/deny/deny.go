// Package deny is the management-plane denylist for planned config lines
// (#10 §6, #29). No flag overrides it; config can add entries, never remove
// one. Any denied line refuses the whole plan.
package deny

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/lcleveland/network-mcp/internal/output"
)

// MaxLines caps one plan.
const MaxLines = 200

// Default is compiled in. A line matches an entry of k tokens when each of
// its first k tokens is a prefix of the entry's token at that position, so
// abbreviations match.
var Default = []string{
	"aaa", "username", "enable", "line", "ip ssh", "crypto", "snmp-server", "boot", "reload", "erase",
	"config-register", "alias", "event manager", "kron", "archive", "parser", "configuration mode", "privilege",
	"banner", "macro", "ip http", "restconf", "netconf-yang", "ip scp", "ip ftp", "ip tftp", "logging", "license",
	"key", "tacacs", "radius", "radius-server", "service internal", "gnxi", "checkpoint", "rollback", "feature",
	// council amendment to #29: session, trust-anchor and prompt protection
	"ssh", "role", "hostname", "switchname", "ip domain-name", "copp", "control-plane",
	// #35: every NX-OS CoPP map, built-in or copied, is type control-plane
	"policy-map type control-plane", "class-map type control-plane",
}

// mode lines would leave global config or run exec commands.
var mode = []string{"do", "end", "exit", "configure"}

// List is Default plus config's write_deny, tokenized.
type List struct{ entries [][]string }

// New adds extra to Default. It never shrinks Default.
func New(extra []string) (List, error) {
	if err := Validate(extra); err != nil {
		return List{}, err
	}
	var l List
	for _, e := range slices.Concat(mode, Default, extra) {
		l.entries = append(l.entries, strings.Fields(strings.ToLower(e)))
	}
	return l, nil
}

// Validate checks write_deny entries.
func Validate(entries []string) error {
	for _, e := range entries {
		if err := chars(e); err != nil || strings.TrimSpace(e) == "" {
			return fmt.Errorf("write_deny entry %q: use one or more words of printable ASCII without ? or |", e)
		}
	}
	return nil
}

// chars allows printable ASCII except ? (help) and | (pipe), so no tab, CR or LF.
func chars(s string) error {
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '?' || r == '|' {
			return fmt.Errorf("character %q is not allowed: use printable ASCII without ? or |", r)
		}
	}
	return nil
}

// Derived are the management-plane objects found in a running config.
type Derived struct {
	ACLs       []string // referenced by access-class, snmp-server, or the connect interface
	VRFs       []string // the management VRF and the connect interface's VRF
	Interfaces []string // owning the address the server connects to
	Policies   []string // CoPP policy-maps: under control-plane, and their children
	Classes    []string // class-maps those policies use, and their nested classes
	AllMaps    bool     // a CoPP name has no block: deny every policy-map and class-map line
}

// Check normalizes the lines (whitespace collapsed) or says why the plan is
// refused. Errors name the line by number and never echo it.
func (l List) Check(lines []string, d Derived) ([]string, error) {
	if len(lines) == 0 || len(lines) > MaxLines {
		return nil, fmt.Errorf("a plan takes 1 to %d lines", MaxLines)
	}
	out := make([]string, len(lines))
	for i, line := range lines {
		if err := chars(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		tok := strings.Fields(strings.ToLower(line))
		if len(tok) == 0 {
			return nil, fmt.Errorf("line %d is empty", i+1)
		}
		// a leading no/default (or its abbreviation) is stripped; deny wins, so every suffix is checked
		for j := range tok {
			if why := l.denied(tok[j:], d); why != "" {
				return nil, fmt.Errorf("line %d: %s; the whole plan is refused", i+1, why)
			}
			if !strings.HasPrefix("no", tok[j]) && !strings.HasPrefix("default", tok[j]) {
				break
			}
		}
		out[i] = strings.Join(strings.Fields(line), " ")
	}
	return out, nil
}

func (l List) denied(tok []string, d Derived) string {
	for _, e := range l.entries {
		if match(tok, e) {
			return fmt.Sprintf("matches the denied %q", strings.Join(e, " "))
		}
	}
	for _, a := range d.ACLs {
		if aclLine(tok, a) {
			return "edits an ACL the management plane uses (access-class, snmp-server or the connect interface)"
		}
	}
	for _, v := range d.VRFs {
		if vrfLine(tok, v) {
			return fmt.Sprintf("touches the management VRF %s or its routes", v)
		}
	}
	for _, f := range d.Interfaces {
		if len(tok) > 1 && strings.HasPrefix("interface", tok[0]) && ifaceLine(tok[1:], f) {
			return fmt.Sprintf("touches interface %s, which owns the address the server connects to", f)
		}
	}
	if mapLine(tok, d) {
		return "edits a policy-map or class-map the control plane uses"
	}
	return ""
}

// mapLine: "policy-map|class-map … <derived name> …", or any such line when AllMaps.
func mapLine(tok []string, d Derived) bool {
	for kw, names := range map[string][]string{"policy-map": d.Policies, "class-map": d.Classes} {
		if strings.HasPrefix(kw, tok[0]) &&
			(d.AllMaps || slices.ContainsFunc(names, func(n string) bool { return slices.Contains(tok[1:], n) })) {
			return true
		}
	}
	return false
}

func match(tok, entry []string) bool {
	if len(tok) < len(entry) {
		return false
	}
	for i, e := range entry {
		if !strings.HasPrefix(e, tok[i]) {
			return false
		}
	}
	return true
}

// aclLine: "ip|ipv6 access-list … <name> …" or "access-list <name> …".
func aclLine(tok []string, name string) bool {
	if strings.HasPrefix("access-list", tok[0]) {
		return len(tok) > 1 && tok[1] == name
	}
	return len(tok) > 2 && (strings.HasPrefix("ip", tok[0]) || strings.HasPrefix("ipv6", tok[0])) &&
		strings.HasPrefix("access-list", tok[1]) && slices.Contains(tok[2:], name)
}

// vrfLine: any "vrf" keyword (or abbreviation) later followed by the name,
// e.g. "vrf context X", "ip route vrf X …", "vrf forwarding X".
func vrfLine(tok []string, name string) bool {
	for i, t := range tok {
		if strings.HasPrefix("vrf", t) && slices.Contains(tok[i+1:], name) {
			return true
		}
	}
	return false
}

// ifaceLine reports whether "interface <rest>" can select iface: abbreviated
// type, optional space before the number, subinterfaces, lists and ranges.
// Anything it cannot parse is treated as a match.
func ifaceLine(rest []string, iface string) bool {
	if len(rest) > 1 && strings.HasPrefix("range", rest[0]) {
		rest = rest[1:]
	}
	etyp, enum := splitIface(iface)
	typ := ""
	for item := range strings.SplitSeq(strings.Join(rest, ""), ",") {
		t, num := splitIface(item)
		if t != "" {
			typ = t
		}
		if typ != "" && !strings.HasPrefix(etyp, typ) {
			continue
		}
		switch {
		case num == "", num == enum, strings.HasPrefix(num, enum+"."), strings.HasPrefix(enum, num+"."):
			return true
		case strings.Contains(num, "-") && inRange(num, enum):
			return true
		}
	}
	return false
}

func splitIface(s string) (typ, num string) {
	i := strings.IndexAny(s, "0123456789")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

// inRange: "1/0/1-4" or "1/0/1-1/0/4" holds enum "1/0/3".
func inRange(num, enum string) bool {
	lo, hi, _ := strings.Cut(num, "-")
	lb, ln, ok1 := splitLast(lo)
	eb, en, ok2 := splitLast(enum)
	_, hn, ok3 := splitLast(hi)
	if !ok1 || !ok2 || !ok3 {
		return true
	}
	return lb == eb && ln <= en && en <= hn
}

func splitLast(s string) (string, int, bool) {
	i := strings.LastIndex(s, "/")
	n, err := strconv.Atoi(s[i+1:])
	return s[:i+1], n, err == nil
}

// Derive finds the management-plane objects in an unredacted running config.
// connect is the address the server dials. Names are lower case.
func Derive(running string, connect netip.Addr) Derived {
	var d Derived
	var blocks []block
	for line := range strings.SplitSeq(output.Sanitize(running), "\n") {
		tok := strings.Fields(strings.ToLower(line))
		if len(tok) == 0 {
			continue
		}
		indented := line[0] == ' '
		switch {
		case !indented && tok[0] == "interface" && len(tok) > 1:
			blocks = append(blocks, block{head: tok, name: strings.Join(tok[1:], "")})
		case !indented:
			blocks = append(blocks, block{head: tok})
		default:
			if len(blocks) > 0 {
				blocks[len(blocks)-1].body = append(blocks[len(blocks)-1].body, tok)
			}
		}
		d.ACLs = append(d.ACLs, after(tok, "access-class", "ipv4", "ipv6")...)
		if tok[0] == "snmp-server" {
			d.ACLs = append(d.ACLs, snmpACLs(tok)...)
		}
		if !indented && len(tok) > 2 && tok[0] == "vrf" &&
			(tok[1] == "context" && tok[2] == "management" || tok[1] == "definition" && strings.HasPrefix(tok[2], "mgmt-")) {
			d.VRFs = append(d.VRFs, tok[2])
		}
	}
	for _, b := range blocks {
		if b.name == "" || !slices.ContainsFunc(b.body, func(t []string) bool { return slices.ContainsFunc(t, isAddr(connect)) }) {
			continue
		}
		d.Interfaces = append(d.Interfaces, b.name)
		for _, t := range b.body {
			d.VRFs = append(d.VRFs, after(t, "forwarding")...)
			d.VRFs = append(d.VRFs, after(t, "member")...)
			d.ACLs = append(d.ACLs, after(t, "access-group")...)
			d.ACLs = append(d.ACLs, after(t, "traffic-filter")...)
		}
	}
	copp(&d, blocks)
	return d
}

// block is a top-level config line and its indented body; name is set for interfaces.
type block struct {
	head []string
	name string
	body [][]string
}

// copp derives the CoPP policies, their classes and the classes' ACLs (#35).
// The worklists grow while they are walked, so each closure runs to a fixed point.
func copp(d *Derived, blocks []block) {
	add := func(s *[]string, n string) {
		if !slices.Contains(*s, n) {
			*s = append(*s, n)
		}
	}
	// a service-policy without a name fails safe
	policy := func(t []string) {
		if len(t) < 2 {
			d.AllMaps = true
		} else {
			add(&d.Policies, t[len(t)-1])
		}
	}
	maps := map[string][][]string{} // "policy-map <name>" or "class-map <name>": body
	for _, b := range blocks {
		switch b.head[0] {
		case "control-plane":
			for _, t := range b.body {
				if t[0] == "service-policy" {
					policy(t)
				}
			}
		case "policy-map", "class-map":
			k := b.head[0] + " " + b.head[len(b.head)-1]
			maps[k] = append(maps[k], b.body...)
		}
	}
	for i := 0; i < len(d.Policies); i++ {
		body, ok := maps["policy-map "+d.Policies[i]]
		d.AllMaps = d.AllMaps || !ok
		for _, t := range body {
			switch {
			case t[0] == "class" && len(t) > 1 && t[len(t)-1] != "class-default":
				add(&d.Classes, t[len(t)-1])
			case t[0] == "service-policy":
				policy(t)
			}
		}
	}
	for i := 0; i < len(d.Classes); i++ {
		body, ok := maps["class-map "+d.Classes[i]]
		d.AllMaps = d.AllMaps || !ok
		for _, t := range body {
			if len(t) > 2 && t[0] == "match" && t[1] == "class-map" {
				add(&d.Classes, t[2])
			}
			for _, a := range after(t, "access-group", "name") {
				add(&d.ACLs, a)
			}
		}
	}
}

// after returns the token following kw, skipping one optional word.
func after(tok []string, kw string, skip ...string) []string {
	var out []string
	for i, t := range tok {
		if t != kw {
			continue
		}
		j := i + 1
		if j < len(tok) && slices.Contains(skip, tok[j]) {
			j++
		}
		if j < len(tok) {
			out = append(out, tok[j])
		}
	}
	return out
}

// snmpACLs: every word after the community string, or after access, use-acl,
// use-ipv4acl or use-ipv6acl, that is not a keyword may name an ACL. The
// community string and the passwords before "access" are never collected.
func snmpACLs(tok []string) []string {
	start := -1
	if len(tok) > 3 && tok[1] == "community" {
		start = 3
	}
	for i, t := range tok {
		if start < 0 && slices.Contains([]string{"access", "use-acl", "use-ipv4acl", "use-ipv6acl"}, t) {
			start = i + 1
		}
	}
	if start < 0 {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(tok[start:]), func(t string) bool {
		return slices.Contains([]string{"view", "ro", "rw", "ipv6", "group", "priority", "use-acl", "use-ipv4acl", "use-ipv6acl"}, t)
	})
}

func isAddr(a netip.Addr) func(string) bool {
	return func(t string) bool {
		t, _, _ = strings.Cut(t, "/")
		b, err := netip.ParseAddr(t)
		return err == nil && b.Unmap() == a.Unmap()
	}
}
