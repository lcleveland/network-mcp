package fixtures

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFixturesAreSanitized scans every committed fixture, third-party ones
// included. Only provenance files (LICENSE, NOTICE, SOURCE) and the
// gitignored testdata/raw are skipped: they name upstream projects, not
// environments, or are never committed.
func TestFixturesAreSanitized(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == filepath.Join(root, "raw") { // gitignored captures awaiting cmd/sanitize
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.SplitN(d.Name(), ".", 2)[0] {
		case "LICENSE", "NOTICE", "SOURCE":
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, v := range Violations(string(b)) {
			t.Errorf("%s: %s (run cmd/sanitize)", p, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestViolations(t *testing.T) {
	clean := []string{
		"ip address 192.0.2.1 255.255.255.0",
		"access-list 10 permit 198.51.100.0 0.0.0.255",
		"ipv6 address 2001:db8::1/64",
		"Base ethernet MAC Address : 00:00:5e:00:53:01",
		"0000.5e00.5302 DYNAMIC Gi1/0/1",
		"dev1.example.net uptime is 1 week, 12:34:56",
		"ntp server ntp.example.org",
		"service password-encryption",
		"username admin secret <removed>",
		"Cisco IOS Software, Version 1.0",
		"Press any key to continue",
		"0.0.0.0/0 via 127.0.0.1",
	}
	for _, s := range clean {
		if v := Violations(s); len(v) != 0 {
			t.Errorf("%q: %v", s, v)
		}
	}
	dirty := []string{
		"ip address 10.1.2.3 255.255.255.0",
		"inet 172.16.0.9",
		"from 192.168.1.20",
		"ipv6 address fd00::1/64",
		"MAC 3c:22:fb:01:02:03",
		"a4b1.c2d3.e4f5 DYNAMIC",
		"hostname core1.corp.acme.com",
		"ip domain name acme.local",
		"username admin secret 5 $1$abcd",
		"snmp-server community s3cr3t RO",
	}
	for _, s := range dirty {
		if v := Violations(s); len(v) == 0 {
			t.Errorf("%q passed the guard", s)
		}
	}
}
