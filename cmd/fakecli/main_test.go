package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "show_version.txt"), []byte("Version 1.0\n"), 0o600)
	log := filepath.Join(dir, "received.log")
	var out strings.Builder
	if err := run("dev1", dir, log, strings.NewReader("show version\rshow nope\rexit\r"), &out); err != nil {
		t.Fatal(err)
	}
	want := "dev1#show version\nVersion 1.0\ndev1#show nope\n% Invalid input detected at '^' marker.\ndev1#exit\n"
	if out.String() != want {
		t.Fatalf("got %q", out.String())
	}
	if b, _ := os.ReadFile(log); string(b) != "show version\nshow nope\nexit\n" {
		t.Fatalf("log %q", b)
	}
}
