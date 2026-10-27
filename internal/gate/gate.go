// Package gate decides whether a free-form CLI command may reach a device.
// A refused command never leaves the server.
package gate

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Deny is compiled in; an Ext can add to it but never shrink it.
var Deny = []string{
	"debug", "undebug", "terminal", "configure", "copy", "more", "reload", "clear",
	"show tech", "show running", "show startup", "show archive", "show file",
	"show key chain", "show snmp community", "show snmp user", "show configuration",
	"display current-configuration", "display saved-configuration",
}

// Allow is the set of full first keywords.
var Allow = []string{"show", "display", "dir", "ping", "traceroute"}

var pingDeny = []string{"repeat", "count", "size", "timeout", "sweep"}

const maxLen = 256

// Ext is a platform's read_allow (extra first keywords) and read_deny (extra
// deny entries). It only adds: deny is checked first, so no allow entry can
// unblock a denied command, and the character set never changes.
type Ext struct {
	Allow, Deny []string
}

// Validate refuses entries outside the character set and multi-word allows.
func (x Ext) Validate() error {
	for _, e := range slices.Concat(x.Allow, x.Deny) {
		if strings.TrimSpace(e) == "" || strings.IndexFunc(e, func(r rune) bool { return !allowedChar(r) }) >= 0 {
			return fmt.Errorf("read_allow/read_deny entry %q: use only letters, digits, spaces and . / : _ , -", e)
		}
	}
	for _, a := range x.Allow {
		if strings.ContainsRune(a, ' ') {
			return fmt.Errorf("read_allow entry %q must be one keyword", a)
		}
	}
	return nil
}

// Check returns the command with whitespace collapsed, or why it is refused.
func Check(cmd string, x Ext) (string, error) {
	for _, r := range cmd {
		if !allowedChar(r) {
			return "", fmt.Errorf("character %q is not allowed: use only letters, digits, spaces and . / : _ , - (no pipes; filter server-side)", r)
		}
	}
	tok := strings.Fields(cmd)
	norm := strings.Join(tok, " ")
	switch {
	case norm == "":
		return "", errors.New("empty command")
	case len(norm) > maxLen:
		return "", fmt.Errorf("command longer than %d bytes", maxLen)
	}
	for _, d := range slices.Concat(Deny, x.Deny) {
		if matches(tok, strings.Fields(d)) {
			return "", fmt.Errorf("command matches the denied %q", d)
		}
	}
	allow := slices.Concat(Allow, x.Allow)
	first := strings.ToLower(tok[0])
	if !slices.ContainsFunc(allow, func(a string) bool { return strings.EqualFold(a, first) }) {
		for _, a := range allow {
			if strings.HasPrefix(strings.ToLower(a), first) {
				return "", fmt.Errorf("abbreviations are not accepted: write %q in full", a)
			}
		}
		return "", fmt.Errorf("only commands starting with %s are allowed", strings.Join(allow, ", "))
	}
	if first == "ping" || first == "traceroute" {
		if len(tok) < 2 {
			return "", fmt.Errorf("%s needs a target", first)
		}
		if len(tok) > 6 {
			return "", fmt.Errorf("%s takes at most 6 tokens", first)
		}
		for _, t := range tok[1:] {
			for _, p := range pingDeny {
				if isWord(t) && strings.HasPrefix(p, strings.ToLower(t)) {
					return "", fmt.Errorf("%s option %q is not allowed", first, p)
				}
			}
		}
	}
	return norm, nil
}

// matches reports whether cmd starts with the deny entry, each token compared
// by prefix either way: "sh run" abbreviates "show running", and
// "show running-config" extends it.
func matches(cmd, deny []string) bool {
	if len(cmd) < len(deny) {
		return false
	}
	for i, d := range deny {
		c := strings.ToLower(cmd[i])
		if !strings.HasPrefix(d, c) && !strings.HasPrefix(c, d) {
			return false
		}
	}
	return true
}

func allowedChar(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" ./:_,-", r)
}

func isWord(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}
