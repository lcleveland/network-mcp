package creds

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ssh-read"), []byte(`{"username":"mcp","password":"hunter2-secret"}`), 0o400)
	os.WriteFile(filepath.Join(dir, "key"), []byte(`{"username":"mcp","private_key":"-----BEGIN KEY-----"}`), 0o400)
	os.WriteFile(filepath.Join(dir, "bad"), []byte(`{"username":"mcp","password":"hunter2-secret","private_key":"x"}`), 0o400)
	os.WriteFile(filepath.Join(dir, "nouser"), []byte(`{"password":"hunter2-secret"}`), 0o400)
	os.WriteFile(filepath.Join(dir, "junk"), []byte(`not json hunter2-secret`), 0o400)

	c, err := Read(dir, "ssh-read")
	if err != nil || c.Username != "mcp" || c.Password != "hunter2-secret" {
		t.Fatalf("Read: %+v %v", c, err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(f, c); strings.Contains(s, "hunter2") {
			t.Errorf("%s leaks the secret: %s", f, s)
		}
	}
	if c, err := Read(dir, "key"); err != nil || c.PrivateKey == "" {
		t.Fatalf("key: %+v %v", c, err)
	}

	for _, ref := range []string{"../etc/passwd", "a/b", "..", "", "x y", "bad", "nouser", "junk", "missing"} {
		_, err := Read(dir, ref)
		if err == nil {
			t.Errorf("Read(%q) succeeded", ref)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("Read(%q) error leaks the secret: %v", ref, err)
		}
	}
}

func TestToken(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nb"), []byte(`{"token":"tok-secret"}`), 0o400)
	os.WriteFile(filepath.Join(dir, "empty"), []byte(`{}`), 0o400)
	os.WriteFile(filepath.Join(dir, "junk"), []byte(`tok-secret`), 0o400)
	if tok, err := Token(dir, "nb"); err != nil || tok != "tok-secret" {
		t.Fatalf("%q %v", tok, err)
	}
	for _, ref := range []string{"empty", "junk", "missing", "../nb"} {
		if _, err := Token(dir, ref); err == nil || strings.Contains(err.Error(), "tok-secret") {
			t.Errorf("Token(%q): %v", ref, err)
		}
	}
}
