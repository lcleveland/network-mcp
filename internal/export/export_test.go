package export

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDir(t *testing.T) {
	base := t.TempDir()
	d := Dir{Name: "local", Root: filepath.Join(base, "root")}
	ctx := context.Background()
	a := NewArtifact("dev1", "running", []byte("hostname dev1\n"), true)

	rs, err := d.Put(ctx, []Artifact{a}, "r")
	if err != nil || len(rs) != 1 || rs[0] != (Receipt{Destination: "local", Changed: true, Ref: "dev1/running.txt"}) {
		t.Fatalf("%v %v", rs, err)
	}
	file := filepath.Join(d.Root, "dev1/running.txt")
	if b, _ := os.ReadFile(file); string(b) != "hostname dev1\n" {
		t.Fatalf("%q", b)
	}
	if rs, _ := d.Put(ctx, []Artifact{a}, "r"); rs[0].Changed {
		t.Fatal("identical artifact rewritten")
	}
	b := NewArtifact("dev1", "running", []byte("hostname dev2\n"), true)
	if rs, _ := d.Put(ctx, []Artifact{b}, "r"); !rs[0].Changed {
		t.Fatal("changed artifact not written")
	}

	// a failed write leaves the old file and no temp file behind
	os.MkdirAll(filepath.Join(d.Root, "dev2/startup.txt"), 0o750)
	if _, err := d.Put(ctx, []Artifact{NewArtifact("dev2", "startup", []byte("x"), true)}, "r"); err == nil {
		t.Fatal("rename over a directory succeeded")
	}
	for _, dev := range []string{"dev1", "dev2"} {
		if es, _ := os.ReadDir(filepath.Join(d.Root, dev)); len(es) != 1 {
			t.Fatalf("%s: %v", dev, es)
		}
	}
}

func TestDirConfined(t *testing.T) {
	base := t.TempDir()
	d := Dir{Name: "local", Root: filepath.Join(base, "root")}
	// a symlink out of the root is not followed
	os.MkdirAll(d.Root, 0o750)
	os.Symlink(base, filepath.Join(d.Root, "dev1"))
	for _, a := range []Artifact{
		{Device: "../x", Kind: "running", Ext: "txt"}, {Device: "..", Kind: "running", Ext: "txt"},
		{Device: "a/b", Kind: "running", Ext: "txt"}, {Device: ".git", Kind: "running", Ext: "txt"},
		{Device: "a\nb", Kind: "running", Ext: "txt"}, {Device: "192.0.2.1", Kind: "running", Ext: "txt"},
		{Device: "dev", Kind: "../running", Ext: "txt"}, {Device: "dev", Kind: "running", Ext: "/txt"},
		{Device: "dev1", Kind: "running", Ext: "txt"},
	} {
		if _, err := d.Put(context.Background(), []Artifact{a}, "r"); err == nil {
			t.Errorf("%q/%q.%q accepted", a.Device, a.Kind, a.Ext)
		}
	}
	if es, _ := os.ReadDir(base); len(es) != 1 {
		t.Fatalf("written outside the root: %v", es)
	}
}
