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
	// the operator's real names, when this checkout has the local list
	terms, err := Denylist(filepath.Join("..", "..", DenylistFile))
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
		text := string(b)
		if strings.HasSuffix(p, ".snmprec") {
			text = Snmprec(text)
		}
		for _, v := range append(Violations(text), Denied(string(b), terms)...) {
			t.Errorf("%s: %s (run cmd/sanitize)", p, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSnmprec(t *testing.T) {
	clean := "# walk\n1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.9.1.1\n1.3.6.1.2.1.2.2.1.6.1|4x|00005e005301\n1.3.6.1.2.1.4.20.1.1.192.0.2.1|64|192.0.2.1\n"
	if v := Violations(Snmprec(clean)); len(v) != 0 {
		t.Errorf("clean: %v", v)
	}
	for _, dirty := range []string{
		"1.3.6.1.2.1.2.2.1.6.1|4x|3c22fb010203",
		"1.3.6.1.2.1.4.20.1.1.1|64|10.1.2.3",
		"1.3.6.1.2.1.4.20.1.1.1|64x|0a010203",
		"1.3.6.1.2.1.1.5.0|4|core1.corp.acme.com",
		"1.3.6.1.2.1.1.5.0|4x|636f7265312e636f72702e61636d652e636f6d",
		"# from 192.168.1.20",
	} {
		if v := Violations(Snmprec(dirty)); len(v) == 0 {
			t.Errorf("%q passed the guard", dirty)
		}
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

func TestDenylist(t *testing.T) {
	p := filepath.Join(t.TempDir(), DenylistFile)
	if terms, err := Denylist(p); terms != nil || err != nil {
		t.Fatalf("absent list: %v %v", terms, err)
	}
	os.WriteFile(p, []byte("# names\n  acme-core-7 \n\nacme.example\n"), 0o600)
	terms, err := Denylist(p)
	if err != nil || strings.Join(terms, ",") != "acme-core-7,acme.example" {
		t.Fatalf("%q %v", terms, err)
	}
	if d := Denied("hostname ACME-Core-7\nip domain name dev1", terms); len(d) != 1 || d[0] != "denylisted acme-core-7" {
		t.Fatalf("%v", d)
	}
}
