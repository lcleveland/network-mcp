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
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/platform"
)

// Groups are the tool groups --tool-groups may name. core is always on.
var Groups = []string{"core", "cli"}

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
			return f, fmt.Errorf("rules[%d]: snmp.version %q (want v2c or v3)", i, r.SNMP.Version)
		}
	}
	return f, platform.Validate(f.Platforms)
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

// Enabled reports whether a tool group is on.
func (c *Config) Enabled(group string) bool {
	return group == "core" || len(c.Groups) == 0 || slices.Contains(c.Groups, group)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
