package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/lcleveland/network-mcp/internal/sshfake"
)

func TestSetup(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	devs := write("devices.yaml", "- {name: dev1, address: 192.0.2.1}\n")
	withDevs := write("a.yaml", "management_prefixes: [192.0.2.0/24]\nsources: [{name: file, type: file, path: "+devs+"}]\n")
	empty := write("b.yaml", "management_prefixes: []\n")
	noenv := func(string) string { return "" }
	mibs := filepath.Join(dir, "mibs")
	os.Mkdir(mibs, 0o700)
	os.WriteFile(filepath.Join(mibs, "BROKEN-MIB.txt"), []byte("BROKEN-MIB DEFINITIONS ::= BEGIN {{\n"), 0o600)

	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "--config"},
		{[]string{"--config", withDevs}, "--credentials-dir"},
		{[]string{"--config", empty, "--credentials-dir", dir}, "management_prefixes"},
		{[]string{"--config", withDevs, "--credentials-dir", dir}, "--known-hosts"},
		{[]string{"--config", withDevs, "--credentials-dir", dir, "--known-hosts", "/dev/null", "--mib-dir", mibs}, "BROKEN-MIB"},
	} {
		if _, err := setup(tc.args, noenv); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.args, err, tc.want)
		}
	}
	d, err := setup([]string{"--config", withDevs, "--credentials-dir", dir, "--known-hosts", "/dev/null"}, noenv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Inv.Get(context.Background(), "dev1"); err != nil {
		t.Fatal(err)
	}
}

func TestHostkey(t *testing.T) {
	s := sshfake.Start(t, &sshfake.Engine{Hostname: "dev1"}, sshfake.Options{})
	var b bytes.Buffer
	if err := hostkey(&b, []string{s.Addr}); err != nil {
		t.Fatal(err)
	}
	// the printed line is exactly the pin the server would need
	pin := strings.TrimSpace(string(must(os.ReadFile(s.KnownHosts))))
	out := b.String()
	if !strings.Contains(out, "# "+ssh.FingerprintSHA256(s.HostKey)+"\n") || !strings.HasSuffix(out, pin+"\n") {
		t.Fatalf("got %q, want the pin %q", out, pin)
	}
	if len(s.Received()) != 0 {
		t.Fatalf("hostkey reached the device: %q", s.Received())
	}
	for _, bad := range [][]string{nil, {"dev1"}, {"192.0.2.1", "extra"}} {
		if err := hostkey(&b, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
