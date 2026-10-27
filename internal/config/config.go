// Package config parses flags, environment and the YAML config file.
//
// The config file holds structure only. Secrets come from credential refs in
// the credentials directory, never from a flag, an env var or the file.
// Safety switches are flags only, never config keys.
package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/lcleveland/network-mcp/internal/change/deny"
	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/platform"
)

// Groups are the tool groups --tool-groups may name. core is always on.
var Groups = []string{"core", "cli", "snmp", "export", "change"}

type Config struct {
	ConfigPath     string
	CredentialsDir string
	KnownHosts     string
	Groups         []string // empty means all
	RequestTimeout time.Duration
	LogLevel       slog.Level
	ShowVersion    bool

	HTTP          bool
	Addr          string
	Path          string
	HTTPAuthToken string // never logged
	AllowAdhoc    bool
	MIBDirs       []string

	AllowConfig       bool // registers the change group; off by default
	AllowSave         bool // adds network_change save; needs AllowConfig
	MaxPendingChanges int

	File File
}

// File is the YAML config file.
type File struct {
	ManagementPrefixes []netip.Prefix `yaml:"management_prefixes"`
	AdhocPrefixes      []netip.Prefix `yaml:"adhoc_prefixes"` // a subset of management_prefixes
	ResolveNames       bool           `yaml:"resolve_names"`  // DNS-resolve a device no source gives an address
	Sources            []Source       `yaml:"sources"`
	Rules              []Rule         `yaml:"rules"`
	// keyed by the sources' platform value, case-insensitively
	Platforms map[string]platform.Config `yaml:"platforms"`
	// export destinations by name; none means no network_export
	Destinations map[string]Destination `yaml:"destinations"`
	WriteDeny    []string               `yaml:"write_deny"` // adds to the compiled-in write denylist, never removes
}

// Destination is one export sink. dir takes path; git also remote, branch,
// credential and known_hosts; s3 credential and the rest.
type Destination struct {
	Type   string `yaml:"type"` // dir | git | s3
	Path   string `yaml:"path"`
	Redact *bool  `yaml:"redact"` // nil means true; false is logged on every export

	Remote     string `yaml:"remote"`      // ssh:// or https://; empty means commit only
	Branch     string `yaml:"branch"`      // default main
	Credential string `yaml:"credential"`  // ref: push login or S3 key
	KnownHosts string `yaml:"known_hosts"` // pins an ssh:// remote's host key; required for one

	Endpoint  string `yaml:"endpoint"` // https://; empty means AWS
	Region    string `yaml:"region"`
	Bucket    string `yaml:"bucket"`
	Prefix    string `yaml:"prefix"`
	PathStyle bool   `yaml:"path_style"`
	Checksum  string `yaml:"checksum"` // when_required | when_supported; default when_required with an endpoint
}

// Source is one inventory source. file takes path; netbox takes the rest.
type Source struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // file | netbox
	Path string `yaml:"path"`

	URL          string            `yaml:"url"`
	TokenRef     string            `yaml:"token_ref"` // credential ref holding JSON {token}
	OptInTag     string            `yaml:"opt_in_tag"`
	AddressOrder []string          `yaml:"address_order"`
	Filters      map[string]string `yaml:"filters"` // extra /api/dcim/devices/ query filters
}

// AddressFields are the NetBox device fields address_order may name.
var AddressFields = []string{"primary_ip4", "primary_ip6", "oob_ip"}

// Rule sets credential refs and SNMP for the devices it matches.
type Rule struct {
	Match    Match  `yaml:"match"`
	ReadRef  string `yaml:"read_ref"`
	WriteRef string `yaml:"write_ref"`
	SNMP     *SNMP  `yaml:"snmp"`
}

type SNMP struct {
	Version string `yaml:"version" json:"version"` // v2c | v3
	Ref     string `yaml:"ref" json:"ref"`
	Port    int    `yaml:"port" json:"port,omitempty"` // 0 means 161
}

// Match is `default`, `adhoc`, or one of {platform|tag|device: value}.
type Match struct{ Kind, Value string }

func (m *Match) UnmarshalYAML(n *yaml.Node) error {
	switch {
	case n.Kind == yaml.ScalarNode && (n.Value == "default" || n.Value == "adhoc"):
		m.Kind = n.Value
	case n.Kind == yaml.MappingNode && len(n.Content) == 2 && slices.Contains([]string{"platform", "tag", "device"}, n.Content[0].Value) &&
		n.Content[1].Kind == yaml.ScalarNode && n.Content[1].Value != "":
		m.Kind, m.Value = n.Content[0].Value, n.Content[1].Value
	default:
		return fmt.Errorf("line %d: match must be default, adhoc or one of {platform|tag|device: value}", n.Line)
	}
	return nil
}

func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("config", c.ConfigPath),
		slog.String("known_hosts", c.KnownHosts),
		slog.Any("groups", c.Groups),
		slog.Any("management_prefixes", c.File.ManagementPrefixes),
		slog.Int("sources", len(c.File.Sources)),
		slog.Bool("http", c.HTTP),
		slog.String("addr", c.Addr),
		slog.Bool("http_auth_set", c.HTTPAuthToken != ""),
		slog.Bool("allow_adhoc", c.AllowAdhoc),
		slog.Bool("allow_config", c.AllowConfig),
		slog.Bool("allow_save", c.AllowSave),
		slog.Int("max_pending_changes", c.MaxPendingChanges),
		slog.Any("mib_dirs", c.MIBDirs),
	)
}

// Parse reads args, the environment (getenv is injected for tests) and the
// config file.
func Parse(args []string, getenv func(string) string) (*Config, error) {
	var (
		c                       Config
		groups, logLevel, hauth string
		stdio                   bool
	)
	fs := flag.NewFlagSet("network-mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.ConfigPath, "config", getenv("NETWORK_MCP_CONFIG"), "YAML config file (env NETWORK_MCP_CONFIG)")
	fs.StringVar(&c.CredentialsDir, "credentials-dir", getenv("CREDENTIALS_DIRECTORY"), "directory of credential refs (env CREDENTIALS_DIRECTORY)")
	fs.StringVar(&c.KnownHosts, "known-hosts", getenv("NETWORK_MCP_KNOWN_HOSTS"), "known_hosts file pinning device host keys (env NETWORK_MCP_KNOWN_HOSTS)")
	fs.StringVar(&groups, "tool-groups", "", "comma-separated tool groups to enable (default all): "+strings.Join(Groups, ","))
	fs.DurationVar(&c.RequestTimeout, "request-timeout", 30*time.Second, "per-request timeout to a device")
	fs.StringVar(&logLevel, "log-level", or(getenv("NETWORK_MCP_LOG_LEVEL"), "info"), "debug|info|warn|error (env NETWORK_MCP_LOG_LEVEL)")
	fs.BoolVar(&stdio, "stdio", false, "serve over stdio (default)")
	fs.BoolVar(&c.HTTP, "http", false, "serve over streamable HTTP")
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8232", "HTTP listen address")
	fs.StringVar(&c.Path, "path", "/mcp", "HTTP MCP endpoint path")
	fs.StringVar(&hauth, "http-auth-token-file", getenv("NETWORK_MCP_HTTP_AUTH_TOKEN_FILE"), "file holding the bearer token HTTP clients must send (env NETWORK_MCP_HTTP_AUTH_TOKEN_FILE)")
	fs.BoolVar(&c.AllowAdhoc, "allow-adhoc", false, "accept an IP literal inside adhoc_prefixes as a device (generic driver, adhoc rule)")
	fs.BoolVar(&c.AllowConfig, "allow-config", false, "enable network_change, which plans, applies, confirms and rolls back config changes with each device's write_ref")
	fs.IntVar(&c.MaxPendingChanges, "max-pending-changes", 1, "applied but unconfirmed changes allowed at once")
	fs.BoolVar(&c.AllowSave, "allow-save", false, "add network_change save (copy running-config startup-config); needs --allow-config")
	fs.Func("mib-dir", "directory of extra MIB modules loaded at startup; repeatable; a module that fails to parse refuses startup", func(s string) error {
		c.MIBDirs = append(c.MIBDirs, s)
		return nil
	})
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if c.ShowVersion {
		return &c, nil
	}
	if stdio && c.HTTP {
		return nil, errors.New("--stdio and --http are mutually exclusive")
	}
	if err := c.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	if c.AllowSave && !c.AllowConfig {
		return nil, errors.New("--allow-save needs --allow-config")
	}
	if c.MaxPendingChanges < 1 {
		return nil, errors.New("--max-pending-changes must be at least 1")
	}
	if c.RequestTimeout <= 0 {
		return nil, errors.New("--request-timeout must be positive")
	}
	if groups != "" {
		for g := range strings.SplitSeq(groups, ",") {
			g = strings.TrimSpace(g)
			if !slices.Contains(Groups, g) {
				return nil, fmt.Errorf("--tool-groups: unknown group %q (want %s)", g, strings.Join(Groups, ","))
			}
			c.Groups = append(c.Groups, g)
		}
	}
	if c.ConfigPath == "" {
		return nil, errors.New("--config (or NETWORK_MCP_CONFIG) is required")
	}
	if c.CredentialsDir == "" {
		return nil, errors.New("--credentials-dir (or CREDENTIALS_DIRECTORY) is required")
	}
	if c.HTTP {
		if err := c.readHTTPAuth(hauth); err != nil {
			return nil, err
		}
	}
	b, err := os.ReadFile(c.ConfigPath)
	if err != nil {
		return nil, err
	}
	if c.File, err = ParseFile(b); err != nil {
		return nil, fmt.Errorf("%s: %w", c.ConfigPath, err)
	}
	if c.AllowAdhoc && len(c.File.AdhocPrefixes) == 0 {
		return nil, errors.New("--allow-adhoc needs adhoc_prefixes in the config file")
	}
	if c.AllowConfig { // only existence and mode: the secret is read fresh per call
		for _, r := range c.File.Rules {
			if r.WriteRef == "" {
				continue
			}
			if err := creds.Private(c.CredentialsDir, r.WriteRef); err != nil {
				return nil, fmt.Errorf("--allow-config: %w", err)
			}
		}
	}
	if c.Enabled("export") { // only existence and mode: refs are read fresh per export
		for n, d := range c.File.Destinations {
			if d.Credential != "" {
				if err := creds.Private(c.CredentialsDir, d.Credential); err != nil {
					return nil, fmt.Errorf("destination %s: %w", n, err)
				}
			}
			if d.KnownHosts != "" {
				if _, err := os.Stat(d.KnownHosts); err != nil {
					return nil, fmt.Errorf("destination %s: known_hosts: %w", n, err)
				}
			}
		}
	}
	// v3 noAuth and authNoPriv live in the ref, so the refs are read once here
	for i, r := range c.File.Rules {
		if r.SNMP != nil {
			if _, err := creds.ReadSNMP(c.CredentialsDir, r.SNMP.Ref, r.SNMP.Version); err != nil {
				return nil, fmt.Errorf("rules[%d].snmp: %w", i, err)
			}
		}
	}
	return &c, nil
}

// readHTTPAuth loads the bearer token from file, else from the credential
// http-auth-token, and refuses an unauthenticated non-loopback listener.
func (c *Config) readHTTPAuth(file string) error {
	if !strings.HasPrefix(c.Path, "/") {
		return errors.New("--path must start with /")
	}
	var err error
	if file != "" {
		c.HTTPAuthToken, err = readSecret(file)
	} else if s, e := readSecret(filepath.Join(c.CredentialsDir, "http-auth-token")); e == nil {
		c.HTTPAuthToken = s
	}
	if err != nil {
		return err
	}
	if c.HTTPAuthToken == "" && !loopback(c.Addr) {
		return fmt.Errorf("refusing to listen on non-loopback %s without --http-auth-token-file", c.Addr)
	}
	return nil
}

// readSecret errors never include the file contents.
func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return s, nil
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// ParseFile decodes and validates the config file. Unknown keys are errors.
func ParseFile(b []byte) (File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return f, err
	}
	if len(f.ManagementPrefixes) == 0 {
		return f, errors.New("management_prefixes is empty: the server connects only to devices inside them")
	}
	for _, a := range f.AdhocPrefixes {
		if !slices.ContainsFunc(f.ManagementPrefixes, func(m netip.Prefix) bool { return m.Bits() <= a.Bits() && m.Contains(a.Addr()) }) {
			return f, fmt.Errorf("adhoc_prefixes: %s is not inside management_prefixes", a)
		}
	}
	seen := map[string]bool{}
	for i := range f.Sources {
		if err := validSource(&f.Sources[i], seen); err != nil {
			return f, err
		}
	}
	for i, r := range f.Rules {
		switch {
		case r.Match.Kind == "":
			return f, fmt.Errorf("rules[%d]: match is required", i)
		case r.ReadRef != "" && !creds.ValidRef(r.ReadRef), r.WriteRef != "" && !creds.ValidRef(r.WriteRef),
			r.SNMP != nil && !creds.ValidRef(r.SNMP.Ref):
			return f, fmt.Errorf("rules[%d]: a ref is not a valid ref name", i)
		case r.SNMP != nil && r.SNMP.Version != "v2c" && r.SNMP.Version != "v3":
			return f, fmt.Errorf("rules[%d]: snmp.version %q (want v2c or v3; v1 is refused)", i, r.SNMP.Version)
		case r.SNMP != nil && (r.SNMP.Port < 0 || r.SNMP.Port > 65535):
			return f, fmt.Errorf("rules[%d]: bad snmp.port %d", i, r.SNMP.Port)
		}
	}
	for n, d := range f.Destinations {
		if !creds.ValidRef(n) {
			return f, fmt.Errorf("destinations: name %q may use only letters, digits, . _ -", n)
		}
		if err := validDestination(&d); err != nil {
			return f, fmt.Errorf("destination %s: %w", n, err)
		}
		f.Destinations[n] = d
	}
	if err := deny.Validate(f.WriteDeny); err != nil {
		return f, err
	}
	return f, platform.Validate(f.Platforms)
}

var branchName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$`)

// validDestination checks d and fills the defaults.
func validDestination(d *Destination) error {
	x := *d // x keeps only the fields d.Type does not take
	x.Type, x.Redact = "", nil
	switch d.Type {
	case "dir":
		x.Path = ""
	case "git":
		x.Path, x.Remote, x.Branch, x.Credential, x.KnownHosts = "", "", "", "", ""
	case "s3":
		x.Endpoint, x.Region, x.Bucket, x.Prefix, x.PathStyle, x.Checksum, x.Credential = "", "", "", "", false, "", ""
	default:
		return fmt.Errorf("unknown type %q (want dir, git or s3)", d.Type)
	}
	if x != (Destination{}) {
		return fmt.Errorf("a field is set that type %s does not take", d.Type)
	}
	if d.Type != "s3" && (!filepath.IsAbs(d.Path) || filepath.Clean(d.Path) == "/") {
		return errors.New("path must be an absolute directory other than /")
	}
	switch d.Type {
	case "dir":
		return nil
	case "git":
		d.Branch = or(d.Branch, "main")
		u, err := url.Parse(d.Remote)
		switch {
		case !branchName.MatchString(d.Branch) || strings.Contains(d.Branch, "..") || strings.HasSuffix(d.Branch, ".lock"):
			return fmt.Errorf("branch %q is not a plain branch name", d.Branch)
		case d.Remote == "":
			if d.Credential != "" || d.KnownHosts != "" {
				return errors.New("credential and known_hosts need a remote")
			}
			return nil
		case err != nil || u.Host == "" || u.RawQuery != "" || u.Scheme != "ssh" && u.Scheme != "https":
			return errors.New("remote must be ssh://[user@]host/path or https://host/path")
		case u.Scheme == "https" && (u.User != nil || d.KnownHosts != ""):
			return errors.New("an https remote takes no userinfo and no known_hosts")
		case u.Scheme == "ssh" && !filepath.IsAbs(d.KnownHosts):
			return errors.New("an ssh remote needs known_hosts, an absolute path: host keys are pinned, never trusted on first use")
		case u.Scheme == "ssh" && u.User != nil && u.User.String() != u.User.Username():
			return errors.New("remote must not carry a password")
		}
	case "s3":
		u, err := url.Parse(d.Endpoint)
		switch {
		case d.Endpoint != "" && (err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != ""):
			return errors.New("endpoint must be https://host[/path], without credentials or query")
		case d.Region == "" || d.Bucket == "" || strings.Contains(d.Bucket, "/"):
			return errors.New("region and bucket are required")
		case strings.HasPrefix(d.Prefix, "/") || slices.Contains(strings.Split(d.Prefix, "/"), "..") || strings.ContainsFunc(d.Prefix, unicode.IsControl):
			return fmt.Errorf("prefix %q must be relative, without ..", d.Prefix)
		}
		if d.Checksum == "" {
			d.Checksum = "when_supported"
			if d.Endpoint != "" { // non-AWS stores may reject the SDK's default checksums
				d.Checksum = "when_required"
			}
		}
		if d.Checksum != "when_required" && d.Checksum != "when_supported" {
			return fmt.Errorf("checksum %q (want when_required or when_supported)", d.Checksum)
		}
	}
	if !creds.ValidRef(d.Credential) {
		return fmt.Errorf("credential %q is not a valid ref name", d.Credential)
	}
	return nil
}

// validSource checks s and fills the NetBox defaults.
func validSource(s *Source, seen map[string]bool) error {
	if s.Name == "" || seen[s.Name] {
		return fmt.Errorf("source names must be set and unique, got %q", s.Name)
	}
	seen[s.Name] = true
	switch s.Type {
	case "file":
		if s.Path == "" || s.URL != "" || s.TokenRef != "" || s.OptInTag != "" || s.AddressOrder != nil || s.Filters != nil {
			return fmt.Errorf("source %s: a file source takes path and nothing else", s.Name)
		}
	case "netbox":
		u, err := url.Parse(s.URL)
		switch {
		case s.Path != "":
			return fmt.Errorf("source %s: a netbox source takes no path", s.Name)
		case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "":
			return fmt.Errorf("source %s: url must be http(s)://host[/path], without credentials or query", s.Name)
		case !creds.ValidRef(s.TokenRef):
			return fmt.Errorf("source %s: token_ref %q is not a valid ref name", s.Name, s.TokenRef)
		case s.OptInTag == "":
			return fmt.Errorf("source %s: opt_in_tag is required; only devices carrying it are opted in", s.Name)
		}
		if s.AddressOrder == nil {
			s.AddressOrder = AddressFields
		}
		for _, a := range s.AddressOrder {
			if !slices.Contains(AddressFields, a) {
				return fmt.Errorf("source %s: address_order entry %q (want %s)", s.Name, a, strings.Join(AddressFields, ", "))
			}
		}
	default:
		return fmt.Errorf("source %s: unknown type %q (want file or netbox)", s.Name, s.Type)
	}
	return nil
}

// Enabled reports whether a tool group is on. change also needs --allow-config;
// snmp is off when no rule configures SNMP.
func (c *Config) Enabled(group string) bool {
	if group == "change" && !c.AllowConfig {
		return false
	}
	if group == "snmp" && !slices.ContainsFunc(c.File.Rules, func(r Rule) bool { return r.SNMP != nil }) {
		return false
	}
	return group == "core" || len(c.Groups) == 0 || slices.Contains(c.Groups, group)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
