// Package inventory merges devices from the configured sources, applies the
// platform table and credential rules, and holds the connect-time gates that
// every device passes before the server dials it.
package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/platform"
)

// Device is a merged record. A source fills only what it knows; credentials
// and SNMP come from rules, never from a source.
type Device struct {
	Name        string            `yaml:"name" json:"name"`
	Address     string            `yaml:"address" json:"address,omitempty"`
	Port        int               `yaml:"port" json:"port,omitempty"`
	Platform    string            `yaml:"platform" json:"platform,omitempty"`
	Tags        []string          `yaml:"tags" json:"tags,omitempty"`
	Driver      string            `yaml:"-" json:"driver,omitempty"`
	Profile     string            `yaml:"-" json:"profile,omitempty"`
	ReadRef     string            `yaml:"-" json:"read_ref,omitempty"`
	WriteRef    string            `yaml:"-" json:"write_ref,omitempty"`
	SNMP        *config.SNMP      `yaml:"-" json:"snmp,omitempty"`
	OptedIn     bool              `yaml:"-" json:"opted_in"` // a static file opts in every device it lists
	Adhoc       bool              `yaml:"-" json:"adhoc,omitempty"`
	Unreachable string            `yaml:"-" json:"unreachable,omitempty"` // why the server will not connect
	Provenance  map[string]string `yaml:"-" json:"provenance,omitempty"`  // field -> source
}

// Source lists partial records; empty fields mean "unknown here".
type Source interface {
	Name() string
	List(ctx context.Context) ([]Device, error)
}

type Health struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	OK      bool   `json:"ok"`
	Devices int    `json:"devices"`
	Error   string `json:"error,omitempty"`
}

// TTL is how long a source's successful List is reused.
const TTL = 60 * time.Second

// AdhocPort is the SSH port of an ad-hoc device; tests move it.
var AdhocPort = 22

type cached struct {
	Source
	typ  string
	mu   sync.Mutex
	at   time.Time
	devs []Device
}

// list serves from cache; a failure is never cached and leaves no stale data.
func (c *cached) list(ctx context.Context) ([]Device, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < TTL {
		return c.devs, nil
	}
	devs, err := c.List(ctx)
	if err != nil {
		c.at, c.devs = time.Time{}, nil
		return nil, err
	}
	c.at, c.devs = time.Now(), devs
	return devs, nil
}

type Inventory struct {
	f     config.File
	adhoc bool
	srcs  []*cached
}

// New merges srcs in the given order.
func New(f config.File, adhoc bool, srcs ...Source) *Inventory {
	inv := &Inventory{f: f, adhoc: adhoc}
	for _, s := range srcs {
		inv.srcs = append(inv.srcs, &cached{Source: s})
	}
	return inv
}

// ManagementPrefixes replaces c.File.ManagementPrefixes with the IPAM
// prefixes of the source that sets management_prefixes, read once at
// startup so a NetBox edit never widens a running server. Only an
// unreachable NetBox falls back to the file's list, when it has one, and
// that reason is returned for the caller to log; any other failure
// refuses startup. With no such source it does nothing.
func ManagementPrefixes(ctx context.Context, c *config.Config) (fallback, err error) {
	s := c.File.PrefixSource()
	if s == nil {
		return nil, nil
	}
	ps, err := newNetBox(*s, c.CredentialsDir).prefixes(ctx)
	switch {
	case errors.Is(err, errUnreachable) && len(c.File.ManagementPrefixes) > 0:
		return err, nil
	case err != nil:
		return nil, fmt.Errorf("source %s: management_prefixes: %w", s.Name, err)
	}
	c.File.ManagementPrefixes = ps
	return nil, config.CheckPrefixes(c.File)
}

// Load builds the configured sources. A broken static file refuses startup;
// NetBox is first read on use.
func Load(c *config.Config) (*Inventory, error) {
	var srcs []Source
	for _, s := range c.File.Sources {
		if s.Type == "netbox" {
			srcs = append(srcs, newNetBox(s, c.CredentialsDir))
			continue
		}
		devs, err := loadFile(s.Path)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.Name, err)
		}
		srcs = append(srcs, fileSource{s.Name, devs})
	}
	inv := New(c.File, c.AllowAdhoc, srcs...)
	for i, s := range c.File.Sources {
		inv.srcs[i].typ = s.Type
	}
	return inv, nil
}

type fileSource struct {
	name string
	devs []Device
}

func (f fileSource) Name() string                           { return f.name }
func (f fileSource) List(context.Context) ([]Device, error) { return f.devs, nil }

func loadFile(path string) ([]Device, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var devs []Device
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&devs); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range devs {
		d := &devs[i]
		k := strings.ToLower(d.Name)
		switch {
		case d.Name == "":
			return nil, fmt.Errorf("device %d: name is required", i)
		case seen[k]:
			return nil, fmt.Errorf("duplicate device name %q (names are case-insensitive)", d.Name)
		case d.Port < 0 || d.Port > 65535:
			return nil, fmt.Errorf("device %s: bad port %d", d.Name, d.Port)
		}
		seen[k], d.OptedIn = true, true
	}
	return devs, nil
}

// list merges every source by name, field by field: the first source that
// sets a field wins. A failed source contributes nothing.
func (inv *Inventory) list(ctx context.Context) (map[string]*Device, []Health) {
	devs := map[string]*Device{}
	var health []Health
	for _, s := range inv.srcs {
		got, err := s.list(ctx)
		h := Health{Name: s.Name(), Type: s.typ, OK: err == nil, Devices: len(got)}
		if err != nil {
			h.Error = err.Error()
		}
		health = append(health, h)
		seen := map[string]bool{}
		for _, d := range got {
			k := strings.ToLower(d.Name)
			m := devs[k]
			if m == nil {
				m = &Device{Name: d.Name, Provenance: map[string]string{}}
				devs[k] = m
			}
			if seen[k] {
				m.Unreachable = fmt.Sprintf("source %s has more than one device named %s", s.Name(), d.Name)
			}
			seen[k] = true
			set := func(field string, empty bool, apply func()) {
				if _, done := m.Provenance[field]; !done && !empty {
					apply()
					m.Provenance[field] = s.Name()
				}
			}
			set("address", d.Address == "", func() { m.Address = d.Address })
			set("port", d.Port == 0, func() { m.Port = d.Port })
			set("platform", d.Platform == "", func() { m.Platform = d.Platform })
			set("tags", len(d.Tags) == 0, func() { m.Tags = d.Tags })
			set("opt_in", !d.OptedIn, func() { m.OptedIn = true })
		}
	}
	for _, d := range devs {
		inv.finish(d)
	}
	return devs, health
}

// finish fills the gaps and applies the platform table and the rules.
func (inv *Inventory) finish(d *Device) {
	if d.Port == 0 {
		d.Port = 22
	}
	p := platform.Resolve(d.Platform, inv.f.Platforms)
	d.Driver, d.Profile = p.Driver, p.Profile
	applyRules(d, inv.f.Rules)
	if d.Address == "" && inv.f.ResolveNames {
		d.Address, d.Provenance["address"] = d.Name, "resolve_names"
	}
	switch {
	case d.Unreachable != "":
	case d.Address == "":
		d.Unreachable = "no source gives an address and resolve_names is off"
	case d.ReadRef == "" && d.SNMP == nil: // SNMP-only is fine; the SSH tools refuse it
		d.Unreachable = "no rule gives a read_ref or snmp"
	}
}

// applyRules resolves each field separately: default < platform < tag <
// device, and among rules of one level the first listed wins. An ad-hoc
// device takes only the adhoc rule. write_ref never falls back to read_ref.
func applyRules(d *Device, rules []config.Rule) {
	best := map[string]int{}
	for _, r := range rules {
		l, ok := ruleLevel(r.Match, d)
		if !ok {
			continue
		}
		pick := func(field string, empty bool, apply func()) {
			if b, done := best[field]; !empty && (!done || l > b) {
				apply()
				best[field] = l
			}
		}
		pick("read_ref", r.ReadRef == "", func() { d.ReadRef = r.ReadRef })
		pick("write_ref", r.WriteRef == "", func() { d.WriteRef = r.WriteRef })
		pick("snmp", r.SNMP == nil, func() { d.SNMP = r.SNMP })
	}
}

func ruleLevel(m config.Match, d *Device) (int, bool) {
	if d.Adhoc != (m.Kind == "adhoc") {
		return 0, false
	}
	switch m.Kind {
	case "platform": // the source's value or the driver it maps to
		return 1, strings.EqualFold(m.Value, d.Platform) || strings.EqualFold(m.Value, d.Driver)
	case "tag":
		return 2, slices.ContainsFunc(d.Tags, func(t string) bool { return strings.EqualFold(t, m.Value) })
	case "device":
		return 3, strings.EqualFold(m.Value, d.Name)
	}
	return 0, true // default, adhoc
}

// Health lists every source and reports how each fared.
func (inv *Inventory) Health(ctx context.Context) []Health {
	_, h := inv.list(ctx)
	return h
}

// List returns every merged device, sorted by name.
func (inv *Inventory) List(ctx context.Context) []*Device {
	devs, _ := inv.list(ctx)
	return slices.SortedFunc(maps.Values(devs), func(a, b *Device) int { return strings.Compare(a.Name, b.Name) })
}

// Get finds a device by name, case-insensitively. With --allow-adhoc, an IP
// literal no source knows becomes an ad-hoc device if it is inside
// adhoc_prefixes: generic driver, adhoc rule only.
func (inv *Inventory) Get(ctx context.Context, name string) (*Device, error) {
	devs, _ := inv.list(ctx)
	if d, ok := devs[strings.ToLower(name)]; ok {
		return d, nil
	}
	a, err := netip.ParseAddr(name)
	switch {
	case err != nil:
		return nil, fmt.Errorf("unknown device %q; network_status lists the inventory sources", name)
	case !inv.adhoc:
		return nil, fmt.Errorf("%s is not in the inventory; ad-hoc addresses need --allow-adhoc", name)
	case !inside(a.Unmap(), inv.f.AdhocPrefixes):
		return nil, fmt.Errorf("ad-hoc address %s is outside adhoc_prefixes", name)
	}
	s := a.Unmap().String()
	d := &Device{Name: s, Address: s, Port: AdhocPort, Driver: platform.Generic, OptedIn: true, Adhoc: true,
		Provenance: map[string]string{"address": "adhoc"}}
	if applyRules(d, inv.f.Rules); d.ReadRef == "" && d.SNMP == nil {
		d.Unreachable = "no adhoc rule gives a read_ref or snmp"
	}
	return d, nil
}

// Lookup resolves a host name; net.DefaultResolver.LookupNetIP with "ip" fits.
type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

// Gate returns the address to dial, or why the device is refused. A name is
// resolved and every address it resolves to must be inside a management
// prefix; the caller dials the returned address, not the name again.
func Gate(ctx context.Context, d *Device, prefixes []netip.Prefix, lookup Lookup) (netip.Addr, error) {
	if !d.OptedIn {
		return netip.Addr{}, fmt.Errorf("device %s is not opted in", d.Name)
	}
	if d.Unreachable != "" {
		return netip.Addr{}, fmt.Errorf("device %s is unreachable: %s", d.Name, d.Unreachable)
	}
	a, _, err := InPrefix(ctx, d, prefixes, lookup)
	return a, err
}

// InPrefix resolves the device address; every address must be inside a
// management prefix. It returns the first address and the prefix holding it.
func InPrefix(ctx context.Context, d *Device, prefixes []netip.Prefix, lookup Lookup) (netip.Addr, netip.Prefix, error) {
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(d.Address); err == nil {
		addrs = append(addrs, a)
	} else {
		var err error
		if addrs, err = lookup(ctx, d.Address); err != nil {
			return netip.Addr{}, netip.Prefix{}, fmt.Errorf("resolving %s: %w", d.Address, err)
		}
		if len(addrs) == 0 {
			return netip.Addr{}, netip.Prefix{}, fmt.Errorf("%s resolved to no address", d.Address)
		}
	}
	for _, a := range addrs {
		if !inside(a.Unmap(), prefixes) {
			return netip.Addr{}, netip.Prefix{}, fmt.Errorf("device %s address %s is outside management_prefixes", d.Name, a.Unmap())
		}
	}
	a := addrs[0].Unmap()
	return a, prefixes[slices.IndexFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) })], nil
}

func inside(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
