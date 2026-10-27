package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "--config"},
		{[]string{"--config", withDevs}, "--credentials-dir"},
		{[]string{"--config", empty, "--credentials-dir", dir}, "management_prefixes"},
		{[]string{"--config", withDevs, "--credentials-dir", dir}, "--known-hosts"},
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
