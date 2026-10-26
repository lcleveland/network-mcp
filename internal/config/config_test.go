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
credentials:
  default: {read_ref: ssh-read}
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
	if len(c.File.ManagementPrefixes) != 2 || c.File.Credentials.Default.ReadRef != "ssh-read" || c.CredentialsDir != dir {
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
		"management_prefixes: [192.0.2.0/24]\npassword: x":                              "password",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: netbox}]":       "unknown type",
		"management_prefixes: [192.0.2.0/24]\nsources: [{name: a, type: file}]":         "path",
		"management_prefixes: [192.0.2.0/24]\ncredentials: {default: {read_ref: ../x}}": "valid ref",
	} {
		if _, err := ParseFile([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}
