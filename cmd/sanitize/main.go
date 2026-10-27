// Command sanitize makes one captured device transcript safe to commit:
//
//	go run ./cmd/sanitize [-denylist .fixture-denylist] < testdata/raw/x.txt > testdata/<dir>/x.txt
//
// Hostnames, addresses, domains, serials, usernames, model and firmware
// strings become documentation values or placeholders; login lines, banners,
// secret lines and timestamps are dropped. Output is deterministic and a value
// maps to one placeholder throughout the file. It prints nothing if the result
// still fails the fixture guard.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lcleveland/network-mcp/internal/fixtures"
)

func main() {
	list := flag.String("denylist", fixtures.DenylistFile, "local file of real names to replace; missing means none")
	flag.Parse()
	terms, err := fixtures.Denylist(*list)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := sanitize(deny(string(in), terms))
	if v := append(fixtures.Violations(out), fixtures.Denied(out, terms)...); len(v) > 0 {
		fmt.Fprintf(os.Stderr, "sanitize: still unsafe, fix the input by hand:\n  %s\n", strings.Join(v, "\n  "))
		os.Exit(1)
	}
	os.Stdout.WriteString(out)
}

var (
	drop   = regexp.MustCompile(`(?i)^\s*last login|\b(mon|tue|wed|thu|fri|sat|sun)\b.*\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)`)
	banner = regexp.MustCompile(`^banner \S+ (\^C|\S)`)
	uptime = regexp.MustCompile(`( uptime is )[^\r\n]*`)

	// Each capture group is a value to replace everywhere in the file by
	// <class><n>. Order sets numbering, so keep it stable.
	rules = []struct {
		class string
		re    *regexp.Regexp
	}{
		{"dev", regexp.MustCompile(`(?m)^hostname[ \t]+(\S+)`)},
		{"dev", regexp.MustCompile(`(?m)^(\S+) uptime is`)},
		{"dev", regexp.MustCompile(`(?m)^(\w[\w.\-@/:]{0,62})(?:\([^)\n]*\))?[>#]`)}, // prompt
		{"user", regexp.MustCompile(`\busername[ \t]+(\S+)`)},
		{"SERIAL", regexp.MustCompile(`(?i)(?:board ID|serial (?:number|num|no\.?)[ \t]*:?|\bSN:)[ \t]*([^\s,]+)`)},
		{"MODEL", regexp.MustCompile(`(?m)^cisco (\S+) \(([^)\n]+)\) processor`)},
		{"MODEL", regexp.MustCompile(`(?i)(?:model number[ \t]*:|\bPID:|\bCatalyst)[ \t]*([^\s,]+)`)},
		{"fw", regexp.MustCompile(`(?i)\bversion[ \t]+(\d[^\s,]*[.(][^\s,]*)`)}, // needs a dot or paren, so "version 2" stays
		{"fw", regexp.MustCompile(`(?m)^ROM:[ \t]+(\d\S*)`)},
		{"fw", regexp.MustCompile(`Software \(([^)\n]+)\)|image file is "([^"\n]+)"`)},
	}
	// Already a placeholder, or a word the rules catch by accident.
	keep = regexp.MustCompile(`^(dev|user|SERIAL|MODEL|fw|term)\d+$|^Kernel$`)

	v4nets = []string{"192.0.2.", "198.51.100.", "203.0.113."}
)

func sanitize(text string) string {
	text = dropLines(text)
	text = uptime.ReplaceAllString(text, "${1}1 week, 2 days, 3 hours, 4 minutes")
	text = names(text)
	text = swap(text, fixtures.MAC, func(m string) string {
		return strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(m))
	}, func(n int, m string) string {
		if n > 255 {
			panic("shortcut: more than 256 MACs in one file")
		}
		if strings.Contains(m, ".") {
			return fmt.Sprintf("0000.5e00.53%02x", n)
		}
		return strings.ReplaceAll("00:00:5e:00:53:", ":", m[2:3]) + fmt.Sprintf("%02x", n)
	})
	text = swap(text, fixtures.IPv4, nil, func(n int, _ string) string {
		if n >= 254*len(v4nets) {
			panic("shortcut: more than 762 IPv4 addresses in one file")
		}
		return v4nets[n/254] + strconv.Itoa(n%254+1)
	})
	text = swap(text, fixtures.IPv6, strings.ToLower, func(n int, _ string) string { return fmt.Sprintf("2001:db8::%x", n+1) })
	return swap(text, fixtures.FQDN, strings.ToLower, func(n int, _ string) string { return fmt.Sprintf("name%d.example.com", n+1) })
}

// deny replaces each denylisted term, ignoring case and longest first, by
// term<n> in list order, catching names the rules cannot see (a hostname in
// NX-OS JSON, a site in an interface description).
func deny(text string, terms []string) string {
	if len(terms) == 0 {
		return text
	}
	repl := map[string]string{}
	var alts []string
	for i, t := range terms {
		repl[strings.ToLower(t)] = "term" + strconv.Itoa(i+1)
		alts = append(alts, regexp.QuoteMeta(t))
	}
	sort.Slice(alts, func(i, j int) bool { return len(alts[i]) > len(alts[j]) })
	return regexp.MustCompile(`(?i)`+strings.Join(alts, "|")).ReplaceAllStringFunc(text, func(m string) string {
		return repl[strings.ToLower(m)]
	})
}

// dropLines removes login lines, timestamps, secret lines and banner blocks.
func dropLines(text string) string {
	var out []string
	end := ""
	for _, l := range strings.Split(text, "\n") {
		if end != "" {
			if strings.Contains(l, end) {
				end = ""
			}
			continue
		}
		if m := banner.FindStringSubmatch(l); m != nil {
			if !strings.Contains(l[len(m[0]):], m[1]) {
				end = m[1]
			}
			continue
		}
		if drop.MatchString(l) || secretLine(l) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func secretLine(l string) bool {
	for _, v := range fixtures.Violations(l) {
		if strings.HasPrefix(v, "secret line") {
			return true
		}
	}
	return false
}

// names replaces every value the rules capture, longest first in one pass so
// a placeholder is never rewritten.
func names(text string) string {
	repl := map[string]string{}
	count := map[string]int{}
	for _, r := range rules {
		for _, m := range r.re.FindAllStringSubmatch(text, -1) {
			for _, v := range m[1:] {
				if v == "" || keep.MatchString(v) || repl[v] != "" {
					continue
				}
				for repl[v] == "" || strings.Contains(text, repl[v]) {
					count[r.class]++
					repl[v] = r.class + strconv.Itoa(count[r.class])
				}
			}
		}
	}
	if len(repl) == 0 {
		return text
	}
	var alts []string
	for v := range repl {
		alts = append(alts, v)
	}
	sort.Slice(alts, func(i, j int) bool {
		return len(alts[i]) > len(alts[j]) || len(alts[i]) == len(alts[j]) && alts[i] < alts[j]
	})
	for i, v := range alts {
		p := regexp.QuoteMeta(v)
		if isWord(v[0]) {
			p = `\b` + p
		}
		if isWord(v[len(v)-1]) {
			p += `\b`
		}
		alts[i] = p
	}
	return regexp.MustCompile(strings.Join(alts, "|")).ReplaceAllStringFunc(text, func(m string) string { return repl[m] })
}

func isWord(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// swap replaces each match the guard rejects by gen(n), where n counts
// distinct keys in order of appearance, skipping values the text already has.
func swap(text string, re *regexp.Regexp, key func(string) string, gen func(n int, m string) string) string {
	seen := map[string]int{}
	n := 0
	return re.ReplaceAllStringFunc(text, func(m string) string {
		if len(fixtures.Violations(m)) == 0 {
			return m
		}
		k := m
		if key != nil {
			k = key(m)
		}
		if _, ok := seen[k]; !ok {
			for strings.Contains(text, gen(n, m)) {
				n++
			}
			seen[k] = n
			n++
		}
		return gen(seen[k], m)
	})
}
