package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const good = `
management_prefixes: [192.0.2.0/24, 2001:db8::/32]
sources:
  - {name: file, type: file, path: /etc/network-mcp/devices.yaml}
rules:
  - {match: default, read_ref: ssh-read}
`

func TestParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(good), 0o600)
	env := map[string]string{"NETWORK_MCP_CONFIG": path, "CREDENTIALS_DIRECTORY": dir}

	c, err := Parse(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(c.File.ManagementPrefixes) != 2 || c.File.Rules[0].ReadRef != "ssh-read" || c.CredentialsDir != dir {
		t.Fatalf("%+v", c)
	}
	if !c.Enabled("cli") || !c.Enabled("core") {
		t.Fatal("all groups on by default")
	}

	c, err = Parse([]string{"--config", path, "--credentials-dir", dir, "--tool-groups", "core"}, func(string) string { return "" })
	if err != nil || c.Enabled("cli") {
		t.Fatalf("core only: %v %v", c, err)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "--config"},
		{[]string{"--config", path}, "--credentials-dir"},
		{[]string{"--config", path, "--credentials-dir", dir, "--tool-groups", "x"}, "unknown group"},
		{[]string{"--config", path, "--credentials-dir", dir, "--allow-adhoc"}, "adhoc_prefixes"},
	} {
		if _, err := Parse(tc.args, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestHTTP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(good), 0o600)
	base := []string{"--config", path, "--credentials-dir", dir, "--http"}
	noenv := func(string) string { return "" }

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--addr", "0.0.0.0:8232"}, "non-loopback"},
		{[]string{"--addr", "192.0.2.1:8232"}, "non-loopback"},
		{[]string{"--path", "mcp"}, "--path"},
		{[]string{"--stdio"}, "mutually exclusive"},
		{[]string{"--http-auth-token-file", filepath.Join(dir, "missing")}, "reading secret"},
	} {
		if _, err := Parse(append(base, tc.args...), noenv); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.args, err, tc.want)
		}
	}

	// loopback needs no token; the credential http-auth-token is picked up
	if c, err := Parse(base, noenv); err != nil || c.Addr != "127.0.0.1:8232" || c.HTTPAuthToken != "" {
		t.Fatalf("%v %v", c, err)
	}
	os.WriteFile(filepath.Join(dir, "http-auth-token"), []byte(" supersecretvalue\n"), 0o600)
	c, err := Parse(append(base, "--addr", "0.0.0.0:8232"), noenv)
	if err != nil || c.HTTPAuthToken != "supersecretvalue" {
		t.Fatalf("%v %v", c, err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "config", c)
	if strings.Contains(buf.String(), "supersecretvalue") || !strings.Contains(buf.String(), "http_auth_set=true") {
		t.Fatalf("log: %s", buf.String())
	}
}

func TestParseFile(t *testing.T) {
	for in, want := range map[string]string{
		``:                            "management_prefixes is empty",
		`management_prefixes: []`:     "management_prefixes is empty",
		`management_prefixes: [nope]`: "nope",
		"management_prefixes: [192.0.2.0/24]\npassword: x":                                                                                                    "password",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: nautobot}]":                                                                           "unknown type",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: file}]":                                                                               "path",
		"management_prefixes: [192.0.2.0/24]\nrules: [{match: default, read_ref: ../x}]":                                                                      "valid ref",
		"management_prefixes: [192.0.2.0/24]\nrules: [{match: {platform: a, tag: b}}]":                                                                        "match must be",
		"management_prefixes: [192.0.2.0/24]\nrules: [{match: everything}]":                                                                                   "match must be",
		"management_prefixes: [192.0.2.0/24]\nrules: [{read_ref: a}]":                                                                                         "match is required",
		"management_prefixes: [192.0.2.0/24]\nrules: [{match: default, snmp: {version: v1, ref: a}}]":                                                         "snmp.version",
		"management_prefixes: [192.0.2.0/24]\nadhoc_prefixes: [192.0.0.0/16]":                                                                                 "not inside",
		"management_prefixes: [192.0.2.0/24]\nadhoc_prefixes: [198.51.100.0/24]":                                                                              "not inside",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: file, path: x, url: y}]":                                                              "path and nothing else",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: netbox, url: 'ftp://x'}]":                                                             "url must be",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: netbox, url: 'https://u:p@x'}]":                                                       "url must be",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: netbox, url: 'https://x'}]":                                                           "token_ref",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: netbox, url: 'https://x', token_ref: t}]":                                             "opt_in_tag",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: netbox, url: 'https://x', token_ref: t, opt_in_tag: m, address_order: [primary_ip]}]": "address_order",
		"management_prefixes: [192.0.2.0/24]\nplatforms: {c9k: {driver: iosxr}}":                                                                              "driver",
		"management_prefixes: [192.0.2.0/24]\nplatforms: {c9k: {profile: junos}}":                                                                             "profile",
		"management_prefixes: [192.0.2.0/24]\nplatforms: {c9k: {drvier: iosxe}}":                                                                              "drvier",
		"management_prefixes: [192.0.2.0/24]\nplatforms: {C9K: {}, c9k: {}}":                                                                                  "repeats",
		"management_prefixes: [192.0.2.0/24]\nplatforms: {c9k: {getters: {x: 'show version | json'}}}":                                                        "character",
		"management_prefixes: [192.0.2.0/24]\nplatforms: {c9k: {read_allow: ['a b']}}":                                                                        "one keyword",
		"management_prefixes: [192.0.2.0/24]\ndestinations: {local: {type: s3, path: /x}}":                                                                    "want dir",
		"management_prefixes: [192.0.2.0/24]\ndestinations: {local: {type: dir, path: x}}":                                                                    "absolute",
		"management_prefixes: [192.0.2.0/24]\ndestinations: {local: {type: dir, path: /}}":                                                                    "absolute",
		"management_prefixes: [192.0.2.0/24]\ndestinations: {../x: {type: dir, path: /x}}":                                                                    "name",
		"management_prefixes: [192.0.2.0/24]\ndestinations: {local: {type: dir, path: /x, url: y}}":                                                           "url",
	} {
		if _, err := ParseFile([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}

func TestParseFileFull(t *testing.T) {
	f, err := ParseFile([]byte(`
management_prefixes: [192.0.2.0/24]
adhoc_prefixes: [192.0.2.128/25]
sources:
  - {name: nb, type: netbox, url: 'https://netbox.example.com', token_ref: nb-token, opt_in_tag: mcp, filters: {site: dc1}}
rules:
  - {match: default, read_ref: ssh-read}
  - {match: {platform: nxos}, read_ref: nxos-read, write_ref: nxos-write}
  - {match: {tag: core}, snmp: {version: v3, ref: snmp-core}}
  - {match: {device: dev1}, read_ref: dev1-read}
  - {match: adhoc, read_ref: adhoc-read}
destinations:
  local: {type: dir, path: /var/lib/network-mcp/export, redact: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Sources[0].AddressOrder; strings.Join(got, ",") != "primary_ip4,primary_ip6,oob_ip" {
		t.Errorf("default address_order: %v", got)
	}
	if d := f.Destinations["local"]; d.Path != "/var/lib/network-mcp/export" || d.Redact == nil || *d.Redact {
		t.Errorf("destination: %+v", d)
	}
	if m := f.Rules[1].Match; m.Kind != "platform" || m.Value != "nxos" || f.Rules[4].Match.Kind != "adhoc" || f.Rules[2].SNMP.Ref != "snmp-core" {
		t.Errorf("%+v", f.Rules)
	}
}

func TestAllowConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(good+"  - {match: {platform: nxos}, write_ref: ssh-write}\nwrite_deny: [spanning-tree]\n"), 0o600)
	base := []string{"--config", path, "--credentials-dir", dir}
	noenv := func(string) string { return "" }

	c, err := Parse(append(base, "--tool-groups", "core,change"), noenv)
	if err != nil || c.Enabled("change") || c.MaxPendingChanges != 1 || c.File.WriteDeny[0] != "spanning-tree" {
		t.Fatalf("change needs --allow-config; a missing write ref is fine without it: %+v %v", c, err)
	}
	if _, err := Parse(append(base, "--allow-config"), noenv); err == nil || !strings.Contains(err.Error(), "ssh-write") {
		t.Fatalf("missing write ref: %v", err)
	}
	ref := filepath.Join(dir, "ssh-write")
	os.WriteFile(ref, []byte(`{"username":"w","password":"write-secret"}`), 0o600)
	for _, mode := range []os.FileMode{0o440, 0o404, 0o602} {
		os.Chmod(ref, mode)
		if _, err := Parse(append(base, "--allow-config"), noenv); err == nil || strings.Contains(err.Error(), "write-secret") {
			t.Errorf("mode %v: %v", mode, err)
		}
	}
	os.Chmod(ref, 0o400)
	c, err = Parse(append(base, "--allow-config", "--max-pending-changes", "3"), noenv)
	if err != nil || !c.Enabled("change") || c.MaxPendingChanges != 3 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := Parse(append(base, "--max-pending-changes", "0"), noenv); err == nil {
		t.Fatal("--max-pending-changes 0 accepted")
	}
	if _, err := ParseFile([]byte("management_prefixes: [192.0.2.0/24]\nwrite_deny: ['a?']")); err == nil {
		t.Fatal("bad write_deny accepted")
	}
}
