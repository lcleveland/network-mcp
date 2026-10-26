// Package inventory loads devices from the configured sources and holds the
// connect-time gates that every device passes before the server dials it.
package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lcleveland/network-mcp/internal/config"
)

type Device struct {
	Name     string   `yaml:"name" json:"name"`
	Address  string   `yaml:"address" json:"address"`
	Port     int      `yaml:"port" json:"port,omitempty"`
	Platform string   `yaml:"platform" json:"platform,omitempty"`
	Tags     []string `yaml:"tags" json:"tags,omitempty"`
	Source   string   `yaml:"-" json:"source"`
	OptedIn  bool     `yaml:"-" json:"opted_in"` // a static file opts in every device it lists
}

type Health struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	OK      bool   `json:"ok"`
	Devices int    `json:"devices"`
	Error   string `json:"error,omitempty"`
}

type Inventory struct {
	devices map[string]*Device // keyed by lower-cased name
	Health  []Health
}

// Load reads every source. A broken static file refuses startup.
func Load(srcs []config.Source) (*Inventory, error) {
	inv := &Inventory{devices: map[string]*Device{}}
	for _, s := range srcs {
		devs, err := loadFile(s.Path)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.Name, err)
		}
		for _, d := range devs {
			k := strings.ToLower(d.Name)
			if _, dup := inv.devices[k]; dup {
				return nil, fmt.Errorf("source %s: duplicate device name %q (names are case-insensitive)", s.Name, d.Name)
			}
			d.Source, d.OptedIn = s.Name, true
			inv.devices[k] = d
		}
		inv.Health = append(inv.Health, Health{Name: s.Name, Type: s.Type, OK: true, Devices: len(devs)})
	}
	return inv, nil
}

func loadFile(path string) ([]*Device, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var devs []*Device
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&devs); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for i, d := range devs {
		if d.Name == "" || d.Address == "" {
			return nil, fmt.Errorf("device %d: name and address are required", i)
		}
		if d.Port == 0 {
			d.Port = 22
		}
		if d.Port < 1 || d.Port > 65535 {
			return nil, fmt.Errorf("device %s: bad port %d", d.Name, d.Port)
		}
	}
	return devs, nil
}

// Get finds a device by name, case-insensitively.
func (inv *Inventory) Get(name string) (*Device, bool) {
	d, ok := inv.devices[strings.ToLower(name)]
	return d, ok
}

func (inv *Inventory) Len() int { return len(inv.devices) }

// Lookup resolves a host name; net.DefaultResolver.LookupNetIP with "ip" fits.
type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

// Gate returns the address to dial, or why the device is refused. A name is
// resolved and every address it resolves to must be inside a management
// prefix; the caller dials the returned address, not the name again.
func Gate(ctx context.Context, d *Device, prefixes []netip.Prefix, lookup Lookup) (netip.Addr, error) {
	if !d.OptedIn {
		return netip.Addr{}, fmt.Errorf("device %s is not opted in", d.Name)
	}
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(d.Address); err == nil {
		addrs = append(addrs, a)
	} else {
		var err error
		if addrs, err = lookup(ctx, d.Address); err != nil {
			return netip.Addr{}, fmt.Errorf("resolving %s: %w", d.Address, err)
		}
		if len(addrs) == 0 {
			return netip.Addr{}, fmt.Errorf("%s resolved to no address", d.Address)
		}
	}
	for _, a := range addrs {
		if !inside(a.Unmap(), prefixes) {
			return netip.Addr{}, fmt.Errorf("device %s address %s is outside management_prefixes", d.Name, a.Unmap())
		}
	}
	return addrs[0].Unmap(), nil
}

func inside(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
