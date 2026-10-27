// Package creds reads named credential refs from the credentials directory
// ($CREDENTIALS_DIRECTORY under systemd). A secret ref is read per use and
// never cached or logged; prefixes_ref, structure rather than a login, is
// read once at startup.
package creds

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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

// Private checks, without reading it, that ref is a regular file only its
// owner can access. systemd hands LoadCredential files over as 0440 with the
// service's own group, so with systemd set group read is accepted too.
func Private(dir, ref string, systemd bool) error {
	if !ValidRef(ref) {
		return fmt.Errorf("credential ref %q: names may use only letters, digits, . _ -", ref)
	}
	fi, err := os.Stat(filepath.Join(dir, ref))
	if err != nil {
		return fmt.Errorf("credential ref %q: %w", ref, errors.Unwrap(err))
	}
	deny, want := os.FileMode(0o077), "no group or world access"
	if systemd {
		deny, want = 0o037, "no world access and at most group read"
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&deny != 0 {
		return fmt.Errorf("credential ref %q: must be a regular file with %s, not %v", ref, want, fi.Mode())
	}
	return nil
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

// GitPush loads a git push login: SSH {username?, private_key}, HTTPS
// {username?, token}. Username defaults to "git".
func GitPush(dir, ref string, ssh bool) (user, secret string, err error) {
	var c struct {
		Username   string `json:"username"`
		PrivateKey string `json:"private_key"`
		Token      string `json:"token"`
	}
	shape := "{username?, token}"
	if ssh {
		shape = "{username?, private_key}"
	}
	if err := load(dir, ref, &c, shape); err != nil {
		return "", "", err
	}
	if secret = c.Token; ssh {
		secret = c.PrivateKey
	}
	if secret == "" {
		return "", "", fmt.Errorf("credential ref %q: needs JSON %s", ref, shape)
	}
	return cmp.Or(c.Username, "git"), secret, nil
}

// S3Key is an S3 access key. Its formatting never shows the secret.
type S3Key struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func (k S3Key) Format(f fmt.State, _ rune) { fmt.Fprint(f, "s3key()") }

// S3 loads an S3 access key from ref, JSON {access_key_id,
// secret_access_key, session_token?}.
func S3(dir, ref string) (S3Key, error) {
	var k S3Key
	if err := load(dir, ref, &k, "{access_key_id, secret_access_key, session_token?}"); err != nil {
		return S3Key{}, err
	}
	if k.AccessKeyID == "" || k.SecretAccessKey == "" {
		return S3Key{}, fmt.Errorf("credential ref %q: needs access_key_id and secret_access_key", ref)
	}
	return k, nil
}

// Prefixes loads JSON {management_prefixes, adhoc_prefixes?} from ref, once
// at startup. A bad CIDR fails as bad JSON, so no prefix reaches the error.
func Prefixes(dir, ref string) (mgmt, adhoc []netip.Prefix, err error) {
	var p struct {
		Management []netip.Prefix `json:"management_prefixes"`
		Adhoc      []netip.Prefix `json:"adhoc_prefixes"`
	}
	err = load(dir, ref, &p, "{management_prefixes: [CIDR...], adhoc_prefixes?: [CIDR...]}")
	return p.Management, p.Adhoc, err
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
