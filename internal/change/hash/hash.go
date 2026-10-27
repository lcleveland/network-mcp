// Package hash fingerprints a running config (#10 §3): SHA-256 of the
// unredacted text after normalization. The text itself never leaves the
// server. Volatile lines are Oxidized's (ios.rb, nxos.rb).
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/lcleveland/network-mcp/internal/output"
)

// volatile lines change without a config change. comment entries follow a
// leading "!" (IOS-XE "! Last ...", NX-OS "!Time: ...").
var (
	plain   = []string{"Building configuration", "Current configuration", "ntp clock-period"}
	comment = []string{"Last configuration change", "NVRAM config last updated", "No configuration change since",
		"Command:", "Running configuration last done", "Time:"}
)

// Normalize drops ANSI, CR, trailing whitespace, volatile lines and blank
// lines (only a banner's text could hold a meaningful one, and banner is a
// denied keyword).
func Normalize(cfg string) string {
	var out []string
	for l := range strings.SplitSeq(output.Sanitize(cfg), "\n") {
		if l = strings.TrimRight(l, " \t"); l != "" && !volatile(l) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func volatile(l string) bool {
	list := plain
	if c, ok := strings.CutPrefix(l, "!"); ok {
		l, list = strings.TrimLeft(c, " "), comment
	}
	for _, p := range list {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// Sum is the hex SHA-256 of the normalized config.
func Sum(cfg string) string {
	h := sha256.Sum256([]byte(Normalize(cfg)))
	return hex.EncodeToString(h[:])
}
