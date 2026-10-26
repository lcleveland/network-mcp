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
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lcleveland/network-mcp/internal/creds"
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

	File File
}

// File is the YAML config file.
type File struct {
	ManagementPrefixes []netip.Prefix `yaml:"management_prefixes"`
	Sources            []Source       `yaml:"sources"`
	Credentials        Credentials    `yaml:"credentials"`
}

type Source struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

type Credentials struct {
	Default CredRule `yaml:"default"`
}

type CredRule struct {
	ReadRef string `yaml:"read_ref"`
}

func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("config", c.ConfigPath),
		slog.String("known_hosts", c.KnownHosts),
		slog.Any("groups", c.Groups),
		slog.Any("management_prefixes", c.File.ManagementPrefixes),
		slog.Int("sources", len(c.File.Sources)),
	)
}

// Parse reads args, the environment (getenv is injected for tests) and the
// config file.
func Parse(args []string, getenv func(string) string) (*Config, error) {
	var (
		c                Config
		groups, logLevel string
		stdio            bool
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
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if c.ShowVersion {
		return &c, nil
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
	b, err := os.ReadFile(c.ConfigPath)
	if err != nil {
		return nil, err
	}
	if c.File, err = ParseFile(b); err != nil {
		return nil, fmt.Errorf("%s: %w", c.ConfigPath, err)
	}
	return &c, nil
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
	seen := map[string]bool{}
	for _, s := range f.Sources {
		switch {
		case s.Name == "" || seen[s.Name]:
			return f, fmt.Errorf("source names must be set and unique, got %q", s.Name)
		case s.Type != "file":
			return f, fmt.Errorf("source %s: unknown type %q (want file)", s.Name, s.Type)
		case s.Path == "":
			return f, fmt.Errorf("source %s: path is required", s.Name)
		}
		seen[s.Name] = true
	}
	if r := f.Credentials.Default.ReadRef; r != "" && !creds.ValidRef(r) {
		return f, fmt.Errorf("credentials.default.read_ref %q is not a valid ref name", r)
	}
	return f, nil
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
