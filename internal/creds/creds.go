// Package creds reads named credential refs from the credentials directory
// ($CREDENTIALS_DIRECTORY under systemd). A ref is read per use and never
// cached or logged.
package creds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var refName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Cred is an SSH login. Its formatting never shows the secret.
type Cred struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

func (c Cred) Format(f fmt.State, _ rune) { fmt.Fprint(f, "cred("+c.Username+")") }

// ValidRef reports whether name is a ref name (no path escape).
func ValidRef(name string) bool {
	return refName.MatchString(name) && name != "." && name != ".."
}

// Read loads an SSH login from ref. Errors never include the file contents.
func Read(dir, ref string) (Cred, error) {
	var c Cred
	if err := load(dir, ref, &c, "{username, password} or {username, private_key}"); err != nil {
		return Cred{}, err
	}
	if c.Username == "" || (c.Password == "") == (c.PrivateKey == "") {
		return Cred{}, fmt.Errorf("credential ref %q: needs username and exactly one of password or private_key", ref)
	}
	return c, nil
}

// Token loads an API token from ref, JSON {token}.
func Token(dir, ref string) (string, error) {
	var t struct{ Token string }
	if err := load(dir, ref, &t, "{token}"); err != nil {
		return "", err
	}
	if t.Token == "" {
		return "", fmt.Errorf("credential ref %q: token is empty", ref)
	}
	return t.Token, nil
}

func load(dir, ref string, v any, shape string) error {
	if !ValidRef(ref) {
		return fmt.Errorf("credential ref %q: names may use only letters, digits, . _ -", ref)
	}
	b, err := os.ReadFile(filepath.Join(dir, ref))
	if err != nil {
		return fmt.Errorf("credential ref %q: %w", ref, errors.Unwrap(err))
	}
	if json.Unmarshal(b, v) != nil {
		return fmt.Errorf("credential ref %q: not JSON %s", ref, shape)
	}
	return nil
}
