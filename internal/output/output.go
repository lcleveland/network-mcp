// Package output is the pipeline every model-bound string passes through
// (#11): sanitize, redact, filter, cap, and fit the result in 60 KiB.
//
// The CLI redaction patterns come from Oxidized (lib/oxidized/model/ios.rb,
// nxos.rb, cmd :secret) and NAPALM (napalm/base/constants.py,
// CISCO_SANITIZE_FILTERS), both Apache-2.0; see NOTICE.
package output

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Caps, counted in runes, and the serialized result budget in bytes.
const (
	FieldCap  = 256 // a structured string field
	LongCap   = 512 // sysDescr-like fields and device_error
	LineCap   = 4096
	MaxResult = 60 << 10
	// room left in MaxResult for the envelope around a text field
	envelope = 4 << 10

	Redacted = "<redacted>"
	HintCLI  = "narrow with include/section"
)

// Truncation tells the model a result is incomplete and how to narrow it.
type Truncation struct {
	Reason string `json:"reason"` // device_limit, rows or bytes
	Shown  int    `json:"shown"`
	Total  int    `json:"total,omitempty"`
	Hint   string `json:"hint"`
}

var (
	ansi    = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
	crlf    = strings.NewReplacer("\r\n", "\n", "\r", "\n")
	privKey = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)
)

// Sanitize strips terminal escapes and invisible or reordering characters.
func Sanitize(s string) string {
	s = crlf.Replace(ansi.ReplaceAllString(strings.ToValidUTF8(s, "�"), ""))
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20, r >= 0x7f && r <= 0x9f, // C0, DEL, C1
			r >= 0x200b && r <= 0x200f, r == 0xfeff, // zero-width
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, // bidi
			r >= 0xe0000 && r <= 0xe007f: // tags
			return -1
		}
		return r
	}, s)
}

type rule struct {
	re   *regexp.Regexp
	repl string
}

func r(re, repl string) rule { return rule{regexp.MustCompile(re), repl} }

// rules run on every line in order.
var rules = []rule{
	r(`^(snmp-server community).*`, `$1 `+Redacted),
	r(`^(snmp-server host \S+(?: vrf \S+)?(?: informs?| traps?)?(?: version (?:1|2c|3 \S+))?) +\S+(.*)$`, `${1} `+Redacted+`${2}`),
	r(`^(snmp-server host.*? )\S+( udp-port \d+)?$`, `${1}`+Redacted+`${2}`),
	r(`^(snmp-server user .*? auth \S+) \S+`, `$1 `+Redacted),
	r(`^(snmp-server user .*? priv(?: (?:aes|aes-128|aes-192|aes-256|3des|des))?(?: (?:128|192|256))?) \S+`, `$1 `+Redacted),
	r(`^(snmp-server mib community-map) \S+(.*)`, `$1 `+Redacted+`$2`),
	r(`^(\s*username .+ (?:password|secret) \d) .+`, `$1 `+Redacted),
	r(`(password \d+) \S+`, `$1 `+Redacted),
	r(`^(enable (?:password|secret)(?: level \d+)? \d) .+`, `$1 `+Redacted),
	r(`^(\s+(?:password|secret)(?: \d{1,2})?) \S+`, `$1 `+Redacted),
	r(`^(\s+aaa root secret \d) .+`, `$1 `+Redacted),
	r(`^(.*wpa-psk ascii \d) \S+`, `$1 `+Redacted),
	r(`^(.*key 7) \d.+`, `$1 `+Redacted),
	r(`^((?:tacacs|radius)-server .*key(?: \d+)?) \S+`, `$1 `+Redacted),
	r(`^(\s+key(?: \d+)?) .+`, `$1 `+Redacted), // key under a "tacacs server" / "radius server" block
	r(`^(crypto isakmp key) \S+ (.*)`, `$1 `+Redacted+` $2`),
	r(`^(\s+ip ospf message-digest-key \d+ md5) .+`, `$1 `+Redacted),
	r(`^(\s+ip ospf authentication-key) .+`, `$1 `+Redacted),
	r(`^(\s+neighbor \S+ password) .+`, `$1 `+Redacted),
	r(`^(\s+vrrp \d+ authentication text) .+`, `$1 `+Redacted),
	r(`^(\s+standby \d+ authentication) .{1,8}$`, `$1 `+Redacted),
	r(`^(\s+standby \d+ authentication md5 key-string) .+?( timeout \d+)?$`, `${1} `+Redacted+`${2}`),
	r(`^(\s+key-string) .+`, `$1 `+Redacted),
	r(`^(\s+ppp (?:chap|pap) password \d) .+`, `$1 `+Redacted),
	r(`^(\s+security wpa psk set-key (?:ascii|hex) \d) .*`, `$1 `+Redacted),
	r(`^(\s+dot1x username \S+ password \d) .*`, `$1 `+Redacted),
	r(`^(\s+mgmtuser username \S+ password \d) .* (secret \d) .*`, `$1 `+Redacted+` $2 `+Redacted),
	r(`^(.*server-key(?: \d)?) \S+`, `$1 `+Redacted),
	r(`^(\s+domain-password) \S+(.*)`, `$1 `+Redacted+`$2`),
	r(`^(\s+pre-shared-key).*`, `$1 `+Redacted),
	r(`\$\d+\$\S+`, Redacted), // type 5/8/9 hashes wherever they appear
}

// catchAll runs on lines no rule changed, keeping the keyword and type digit.
var catchAll = r(`(?i)(password|secret|key|community|psk|passphrase)(\s+\d)?\s+\S+`, `${1}${2} `+Redacted)

// hints holds a substring every rule needs, so most lines skip the regexes.
var hints = []string{"pass", "secret", "key", "communit", "psk", "snmp-server", "authentication", "$"}

// Redact replaces secrets with <redacted> and counts the values replaced.
// Over-redaction is accepted. Run it on sanitized text.
func Redact(s string) (string, int) {
	n := strings.Count(s, Redacted)
	s = privKey.ReplaceAllString(s, "-----BEGIN ${1}PRIVATE KEY----- "+Redacted)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		low := strings.ToLower(l)
		if !containsAny(low, hints) {
			continue
		}
		for _, ru := range rules {
			l = ru.re.ReplaceAllString(l, ru.repl)
		}
		if l == lines[i] {
			l = catchAll.re.ReplaceAllString(l, catchAll.repl)
		}
		lines[i] = l
	}
	s = strings.Join(lines, "\n")
	return s, max(strings.Count(s, Redacted)-n, 0)
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// RedactJSON blanks secret-named keys anywhere in decoded JSON and redacts
// every other string. It returns the new value and the count.
func RedactJSON(v any) (any, int) {
	switch t := v.(type) {
	case map[string]any:
		n := 0
		for k, x := range t {
			if secretKey(k) {
				t[k] = Redacted
				n++
				continue
			}
			var c int
			t[k], c = RedactJSON(x)
			n += c
		}
		return t, n
	case []any:
		n := 0
		for i, x := range t {
			var c int
			t[i], c = RedactJSON(x)
			n += c
		}
		return t, n
	case string:
		return Redact(Sanitize(t))
	}
	return v, 0
}

// secretKey ignores case and punctuation, so api_key and private-key count.
func secretKey(k string) bool {
	k = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(k))
	return k == "key" || containsAny(k, []string{"psk", "secret", "password", "passphrase", "apikey", "privatekey", "community"})
}

// Cap keeps max runes and marks the cut with …[+N].
func Cap(s string, max int) string {
	n := utf8.RuneCountInString(s)
	if n <= max {
		return s
	}
	i := 0
	for range max {
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	return fmt.Sprintf("%s…[+%d]", s[:i], n-max)
}

// Field runs one structured string through sanitize, redact and cap.
func Field(s string, max int) (string, int) {
	s, n := Redact(Sanitize(s))
	return Cap(s, max), n
}

// Text runs raw device text through the whole pipeline. limited says the
// read stopped at the device limit. The redaction count covers the whole
// read, filtered-out lines included.
func (f *Filter) Text(raw string, limited bool) (string, int, *Truncation) {
	s, n := Redact(Sanitize(raw))
	lines := f.apply(strings.Split(s, "\n"))
	var tr *Truncation
	size := 0
	for i, l := range lines {
		l = Cap(l, LineCap)
		lines[i] = l
		b, _ := json.Marshal(l)
		if size += len(b); size > MaxResult-envelope { // quotes stand in for the \n escape
			tr = &Truncation{Reason: "bytes", Shown: i, Total: len(lines), Hint: HintCLI}
			lines = lines[:i]
			break
		}
	}
	if limited {
		tr = &Truncation{Reason: "device_limit", Shown: len(lines),
			Hint: "the device sent more than 16 MiB; use a narrower command"}
	}
	return strings.Join(lines, "\n"), n, tr
}
