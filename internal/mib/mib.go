// Package mib maps MIB names to numeric OIDs and back, offline. It keeps
// gosmi (a dormant library with global, unlocked state) behind three
// functions: Load once at startup, then only OID and Name.
//
// mibs/ holds net-snmp's IETF and IANA MIB modules (nixpkgs net-snmp
// 5.9.5.2, share/snmp/mibs, without the NET-SNMP-* and UCD-* modules), each
// with its own copyright notice, and net-snmp's COPYING.
package mib

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/sleepinggenius2/gosmi"
	"github.com/sleepinggenius2/gosmi/smi"
	"github.com/sleepinggenius2/gosmi/types"
)

//go:embed mibs/*.txt
var embedded embed.FS

// Load parses every operator module in dirs, then the embedded set; an
// operator module of the same name wins. Any module that fails to parse is
// an error. Not safe for concurrent use: call it before serving.
func Load(dirs ...string) error {
	gosmi.Init()
	sub, _ := fs.Sub(embedded, "mibs")
	var paths []smi.NamedFS
	for _, d := range dirs {
		paths = append(paths, gosmi.NamedFS(d, os.DirFS(d).(fs.ReadDirFS)))
	}
	paths = append(paths, gosmi.NamedFS("embedded", sub.(fs.ReadDirFS)))
	gosmi.SetFS(paths...)
	for _, p := range paths {
		ents, err := p.FS.ReadDir(".")
		if err != nil {
			return fmt.Errorf("MIB dir %s: %w", p.Name, err)
		}
		for _, e := range ents {
			name, ext, _ := strings.Cut(e.Name(), ".")
			if e.IsDir() || !(ext == "" || ext == "txt" || ext == "mib" || ext == "my" || ext == "mi2") {
				continue
			}
			// GetModule, not LoadModule: LoadModule prints errors to stdout, the stdio transport
			if _, err := gosmi.GetModule(name); err != nil {
				return fmt.Errorf("MIB dir %s: module %s (file %s) failed to parse or load", p.Name, name, e.Name())
			}
		}
	}
	return nil
}

// OID turns "IF-MIB::ifDescr.1", "ifDescr.1" or a numeric OID (leading dot
// optional) into a dotted numeric OID without the leading dot.
func OID(s string) (string, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if numeric(s) {
		return s, nil
	}
	mod, name, qualified := strings.Cut(s, "::")
	if !qualified {
		mod, name = "", s
	}
	name, suffix, _ := strings.Cut(name, ".")
	var (
		n   gosmi.SmiNode
		err error
	)
	switch {
	case name == "" || suffix != "" && !numeric(suffix):
		return "", fmt.Errorf("bad OID %q: want MODULE::name[.index], name[.index] or numeric", s)
	case !qualified:
		n, err = gosmi.GetNode(name)
	case !gosmi.IsLoaded(mod): // GetModule would load it, mutating the shared state
		err = os.ErrNotExist
	default:
		m, _ := gosmi.GetModule(mod)
		n, err = m.GetNode(name)
	}
	if err != nil {
		return "", fmt.Errorf("unknown MIB name %q; use a numeric OID or a name from a loaded module", s)
	}
	oid := n.RenderNumeric()
	if suffix != "" {
		oid += "." + suffix
	}
	return oid, nil
}

// Name renders a numeric OID as MODULE::node plus any index, by its longest
// known prefix, or "" when no loaded module covers it.
func Name(oid string) string {
	o, err := types.OidFromString(strings.TrimPrefix(oid, "."))
	if err != nil || len(o) == 0 {
		return ""
	}
	n, err := gosmi.GetNodeByOID(o)
	if err != nil || int(n.OidLen) > len(o) {
		return ""
	}
	name := n.RenderQualified()
	for _, x := range o[n.OidLen:] {
		name += "." + strconv.FormatUint(uint64(x), 10)
	}
	return name
}

// numeric reports whether s is a dotted list of sub-identifiers.
func numeric(s string) bool {
	for p := range strings.SplitSeq(s, ".") {
		// canonical only: "018" would slip past the denied-subtree prefix check
		if _, err := strconv.ParseUint(p, 10, 32); err != nil || len(p) > 1 && p[0] == '0' {
			return false
		}
	}
	return s != ""
}
