package mib

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"IF-MIB::ifDescr":         "1.3.6.1.2.1.2.2.1.2",
		"ifDescr.5":               "1.3.6.1.2.1.2.2.1.2.5",
		"SNMPv2-MIB::sysUpTime.0": "1.3.6.1.2.1.1.3.0",
		".1.3.6.1.2.1.1.5.0":      "1.3.6.1.2.1.1.5.0",
		"1.3.6.1.4.1.9.9.9":       "1.3.6.1.4.1.9.9.9", // numeric always works
	} {
		if got, err := OID(in); err != nil || got != want {
			t.Errorf("OID(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for in, want := range map[string]string{
		"1.3.6.1.2.1.2.2.1.2":    "IF-MIB::ifDescr",
		".1.3.6.1.2.1.2.2.1.2.5": "IF-MIB::ifDescr.5",
		"1.3.6.1.2.1.1.3":        "SNMPv2-MIB::sysUpTime",
		"1.3.6.1.2.1.1.5.0":      "SNMPv2-MIB::sysName.0",
	} {
		if got := Name(in); got != want {
			t.Errorf("Name(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"noSuchThing", "NOPE-MIB::ifDescr", "ifDescr.x", "", "IF-MIB::"} {
		if got, err := OID(bad); err == nil {
			t.Errorf("OID(%q) = %q, want an error", bad, got)
		}
	}
}

func TestLoadDirs(t *testing.T) {
	t.Cleanup(func() { Load() })
	good := t.TempDir()
	os.WriteFile(filepath.Join(good, "TEST-MIB.txt"), []byte(`TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM SNMPv2-SMI;
testRoot OBJECT IDENTIFIER ::= { enterprises 32473 1 }
END
`), 0o600)
	if err := Load(good); err != nil {
		t.Fatal(err)
	}
	if got, err := OID("TEST-MIB::testRoot.7"); err != nil || got != "1.3.6.1.4.1.32473.1.7" {
		t.Errorf("operator MIB: %q, %v", got, err)
	}
	broken := t.TempDir()
	os.WriteFile(filepath.Join(broken, "BROKEN-MIB.txt"), []byte("BROKEN-MIB DEFINITIONS ::= BEGIN garbage {{ END\n"), 0o600)
	if err := Load(broken); err == nil {
		t.Error("a broken MIB file loaded")
	}
}
