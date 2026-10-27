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
	"strings"

	"github.com/gosnmp/gosnmp"
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

// SNMP is an SNMP credential: v2c JSON {community}; v3 JSON {username,
// auth_protocol, auth_password, priv_protocol, priv_password}, authPriv
// only. Its formatting never shows a secret.
type SNMP struct {
	Version      string `json:"-"`
	Community    string `json:"community"`
	Username     string `json:"username"`
	AuthProtocol string `json:"auth_protocol"`
	AuthPassword string `json:"auth_password"`
	PrivProtocol string `json:"priv_protocol"`
	PrivPassword string `json:"priv_password"`
}

func (c SNMP) Format(f fmt.State, _ rune) { fmt.Fprint(f, "snmp("+c.Version+" "+c.Username+")") }

// The protocol names a v3 ref may use (any case), as gosnmp spells them.
var (
	SNMPAuth = map[string]gosnmp.SnmpV3AuthProtocol{"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224,
		"SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512}
	SNMPPriv = map[string]gosnmp.SnmpV3PrivProtocol{"DES": gosnmp.DES, "AES": gosnmp.AES, "AES192": gosnmp.AES192,
		"AES256": gosnmp.AES256, "AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C}
)

// ReadSNMP loads an SNMP credential for version v2c or v3. v1, noAuth and
// authNoPriv are refused. Errors never include the file contents.
func ReadSNMP(dir, ref, version string) (SNMP, error) {
	c := SNMP{Version: version}
	switch version {
	case "v2c":
		if err := load(dir, ref, &c, "{community}"); err != nil {
			return SNMP{}, err
		}
		if c.Community == "" {
			return SNMP{}, fmt.Errorf("credential ref %q: v2c needs a community", ref)
		}
	case "v3":
		if err := load(dir, ref, &c, "{username, auth_protocol, auth_password, priv_protocol, priv_password}"); err != nil {
			return SNMP{}, err
		}
		_, auth := SNMPAuth[strings.ToUpper(c.AuthProtocol)]
		_, priv := SNMPPriv[strings.ToUpper(c.PrivProtocol)]
		switch {
		case c.Username == "":
			return SNMP{}, fmt.Errorf("credential ref %q: v3 needs a username", ref)
		case !auth || c.AuthPassword == "":
			return SNMP{}, fmt.Errorf("credential ref %q: v3 must be authPriv; noAuth is refused: set auth_password and auth_protocol (MD5, SHA, SHA224, SHA256, SHA384 or SHA512)", ref)
		case !priv || c.PrivPassword == "":
			return SNMP{}, fmt.Errorf("credential ref %q: v3 must be authPriv; authNoPriv is refused: set priv_password and priv_protocol (DES, AES, AES192, AES256, AES192C or AES256C)", ref)
		}
	default:
		return SNMP{}, fmt.Errorf("SNMP version %q is refused: use v2c or v3 authPriv", version)
	}
	return c, nil
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
