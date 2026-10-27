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

func TestReadSNMP(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"v2":         `{"community":"fake-community"}`,
		"v3":         `{"username":"mcp","auth_protocol":"sha256","auth_password":"fake-auth-pass","priv_protocol":"AES","priv_password":"fake-priv-pass"}`,
		"noauth":     `{"username":"mcp"}`,
		"authnopriv": `{"username":"mcp","auth_protocol":"SHA","auth_password":"fake-auth-pass"}`,
		"badproto":   `{"username":"mcp","auth_protocol":"ROT13","auth_password":"fake-auth-pass","priv_protocol":"AES","priv_password":"fake-priv-pass"}`,
		"empty":      `{}`,
	} {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o400)
	}
	if c, err := ReadSNMP(dir, "v2", "v2c"); err != nil || c.Community != "fake-community" {
		t.Fatalf("v2c: %v", err)
	}
	c, err := ReadSNMP(dir, "v3", "v3")
	if err != nil || c.PrivPassword != "fake-priv-pass" {
		t.Fatalf("v3: %v", err)
	}
	if s := fmt.Sprintf("%v %+v %#v %s", c, c, c, c); strings.Contains(s, "fake-") {
		t.Errorf("formatting leaks a secret: %s", s)
	}
	for _, tc := range [][3]string{
		{"noauth", "v3", "noAuth"}, {"authnopriv", "v3", "authNoPriv"}, {"badproto", "v3", "auth_protocol"},
		{"empty", "v2c", "community"}, {"v2", "v1", "refused"}, {"missing", "v2c", "missing"},
	} {
		_, err := ReadSNMP(dir, tc[0], tc[1])
		if err == nil || !strings.Contains(err.Error(), tc[2]) || strings.Contains(err.Error(), "fake-") {
			t.Errorf("%v: %v", tc, err)
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

func TestSinkRefs(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"ssh":   `{"private_key":"fake-key-secret"}`,
		"https": `{"username":"bot","token":"fake-token-secret"}`,
		"s3":    `{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"fake-s3-secret"}`,
		"s3bad": `{"access_key_id":"AKIAIOSFODNN7EXAMPLE"}`,
	} {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o400)
	}
	if u, s, err := GitPush(dir, "ssh", true); err != nil || u != "git" || s != "fake-key-secret" {
		t.Fatalf("ssh: %q %v", u, err)
	}
	if u, s, err := GitPush(dir, "https", false); err != nil || u != "bot" || s != "fake-token-secret" {
		t.Fatalf("https: %q %v", u, err)
	}
	if _, _, err := GitPush(dir, "https", true); err == nil || strings.Contains(err.Error(), "fake") {
		t.Fatalf("token as ssh key: %v", err)
	}
	k, err := S3(dir, "s3")
	if err != nil || k.SecretAccessKey != "fake-s3-secret" || strings.Contains(fmt.Sprintf("%+v", k), "fake") {
		t.Fatalf("s3: %v %v", k, err)
	}
	if _, err := S3(dir, "s3bad"); err == nil {
		t.Fatal("s3 without secret accepted")
	}
}
