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

// Read loads ref from dir. Errors never include the file contents.
func Read(dir, ref string) (Cred, error) {
	if !ValidRef(ref) {
		return Cred{}, fmt.Errorf("credential ref %q: names may use only letters, digits, . _ -", ref)
	}
	b, err := os.ReadFile(filepath.Join(dir, ref))
	if err != nil {
		return Cred{}, fmt.Errorf("credential ref %q: %w", ref, errors.Unwrap(err))
	}
	var c Cred
	if json.Unmarshal(b, &c) != nil {
		return Cred{}, fmt.Errorf("credential ref %q: not JSON {username, password} or {username, private_key}", ref)
	}
	if c.Username == "" || (c.Password == "") == (c.PrivateKey == "") {
		return Cred{}, fmt.Errorf("credential ref %q: needs username and exactly one of password or private_key", ref)
	}
	return c, nil
}
