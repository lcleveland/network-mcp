package inventory

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/config"
)

var ctx = context.Background()

func write(t *testing.T, body string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "devices.yaml")
	os.WriteFile(p, []byte(body), 0o600)
	return &config.Config{File: config.File{
		Sources: []config.Source{{Name: "file", Type: "file", Path: p}},
		Rules:   []config.Rule{{Match: config.Match{Kind: "default"}, ReadRef: "ssh-read"}},
	}}
}

func TestLoad(t *testing.T) {
	inv, err := Load(write(t, `
- {name: dev1, address: 192.0.2.10, platform: cisco_ios, tags: [core]}
- {name: dev2, address: dev2.example.net, port: 2222}
`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := inv.Get(ctx, "DEV1")
	if err != nil || d.Port != 22 || !d.OptedIn || d.Provenance["address"] != "file" || d.ReadRef != "ssh-read" || d.Unreachable != "" {
		t.Fatalf("%+v %v", d, err)
	}
	if h := inv.Health(ctx); len(h) != 1 || h[0].Devices != 2 || !h[0].OK || h[0].Type != "file" {
		t.Fatalf("%+v", h)
	}

	for body, want := range map[string]string{
		"- {name: a, address: 192.0.2.1}\n- {name: A, address: 192.0.2.2}": "duplicate",
		"- {address: 192.0.2.1}":                       "name",
		"- {name: a, address: 192.0.2.1, password: x}": "password",
		"- {name: a, address: 192.0.2.1, port: 70000}": "port",
	} {
		if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
}

type fake struct {
	name  string
	devs  []Device
	err   error
	calls int
}

func (f *fake) Name() string { return f.name }
func (f *fake) List(context.Context) ([]Device, error) {
	f.calls++
	return f.devs, f.err
}

var defaultRule = []config.Rule{{Match: config.Match{Kind: "default"}, ReadRef: "ssh-read"}}

func TestMerge(t *testing.T) {
	file := &fake{name: "file", devs: []Device{
		{Name: "dev1", Platform: "nxos", OptedIn: true}, // patches NetBox's missing platform
		{Name: "dev2", Address: "192.0.2.2", OptedIn: true},
		{Name: "dev3", Address: "192.0.2.3", OptedIn: true},
	}}
	nb := &fake{name: "nb", devs: []Device{
		{Name: "DEV1", Address: "192.0.2.1", Tags: []string{"mcp"}, OptedIn: true},
		{Name: "dev2", Platform: "iosxe", Tags: []string{"mcp"}, OptedIn: true}, // file patches the address
		{Name: "dev4", Address: "192.0.2.4", Port: 2222, Tags: []string{"mcp"}, OptedIn: true},
	}}
	inv := New(config.File{Rules: defaultRule}, false, file, nb)

	d, _ := inv.Get(ctx, "dev1")
	want := map[string]string{"opt_in": "file", "platform": "file", "address": "nb", "tags": "nb"}
	if d.Address != "192.0.2.1" || d.Platform != "nxos" || d.Driver != "nxos" || fmt.Sprint(d.Provenance) != fmt.Sprint(want) {
		t.Fatalf("dev1: %+v", d)
	}
	if d, _ := inv.Get(ctx, "dev2"); d.Address != "192.0.2.2" || d.Driver != "iosxe" || d.Provenance["address"] != "file" || d.Provenance["platform"] != "nb" {
		t.Fatalf("dev2: %+v", d)
	}
	for _, n := range []string{"dev3", "dev4"} {
		if d, err := inv.Get(ctx, n); err != nil || d.Unreachable != "" {
			t.Fatalf("%s from one source: %+v %v", n, d, err)
		}
	}
	if d, _ := inv.Get(ctx, "dev4"); d.Port != 2222 || d.Driver != "generic_ssh" {
		t.Fatalf("dev4: %+v", d)
	}
	if nb.calls != 1 {
		t.Fatalf("List called %d times within the TTL", nb.calls)
	}

	// a failing source: its fields are gone, not stale, and health says so
	nb.err = errors.New("netbox: GET /api/dcim/devices/: 503 Service Unavailable")
	inv = New(config.File{Rules: defaultRule}, false, file, nb)
	d, _ = inv.Get(ctx, "dev1")
	if d.Address != "" || d.Unreachable == "" {
		t.Fatalf("dev1 kept the failed source's address: %+v", d)
	}
	if _, err := inv.Get(ctx, "dev4"); err == nil {
		t.Fatal("dev4 from the failed source is still listed")
	}
	if h := inv.Health(ctx); h[0].OK != true || h[1].OK || !strings.Contains(h[1].Error, "503") {
		t.Fatalf("%+v", h)
	}
	nb.err = nil
	if d, _ := inv.Get(ctx, "dev1"); d.Address != "192.0.2.1" {
		t.Fatal("a failure was cached")
	}

	// two NetBox devices with one name are not merged into one
	dup := &fake{name: "nb", devs: []Device{{Name: "x", Address: "192.0.2.5", OptedIn: true}, {Name: "X", Address: "192.0.2.6", OptedIn: true}}}
	if d, _ := New(config.File{Rules: defaultRule}, false, dup).Get(ctx, "x"); !strings.Contains(d.Unreachable, "more than one") {
		t.Fatalf("%+v", d)
	}
}

func TestRules(t *testing.T) {
	rule := func(kind, value, read, write string, snmp string) config.Rule {
		r := config.Rule{Match: config.Match{Kind: kind, Value: value}, ReadRef: read, WriteRef: write}
		if snmp != "" {
			r.SNMP = &config.SNMP{Version: "v3", Ref: snmp}
		}
		return r
	}
	rules := []config.Rule{
		rule("device", "dev1", "dev1-read", "", ""), // listed first, still wins only by level
		rule("tag", "edge", "", "", "snmp-edge"),
		rule("tag", "core", "", "", "snmp-core"),
		rule("platform", "nxos", "nxos-read", "nxos-write", ""),
		rule("default", "", "ssh-read", "", "snmp-default"),
		rule("adhoc", "", "adhoc-read", "", ""),
	}
	src := &fake{name: "file", devs: []Device{
		{Name: "dev1", Address: "192.0.2.1", Platform: "cisco-nx-os", Tags: []string{"core", "edge"}, OptedIn: true},
		{Name: "dev2", Address: "192.0.2.2", Platform: "NXOS", OptedIn: true},
		{Name: "dev3", Address: "192.0.2.3", Platform: "ios", OptedIn: true},
	}}
	inv := New(config.File{Rules: rules}, false, src)
	for name, want := range map[string]string{
		// device > platform for read; platform write; first tag rule listed wins over default
		"dev1": "dev1-read nxos-write snmp-edge",
		"dev2": "nxos-read nxos-write snmp-default",
		"dev3": "ssh-read  snmp-default", // no write_ref fallback to read_ref
	} {
		d, _ := inv.Get(ctx, name)
		if got := d.ReadRef + " " + d.WriteRef + " " + d.SNMP.Ref; got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}

	inv = New(config.File{Rules: rules[:4]}, false, src)
	if d, _ := inv.Get(ctx, "dev3"); d.Unreachable != "no rule gives a read_ref or snmp" {
		t.Fatalf("no read ref: %+v", d)
	}
	if _, err := Gate(ctx, must(inv.Get(ctx, "dev3")), nil, nil); err == nil || !strings.Contains(err.Error(), "read_ref") {
		t.Fatalf("gate: %v", err)
	}
	// SNMP-only: reachable; the SSH tools refuse it for want of a read_ref
	inv = New(config.File{Rules: append(rules[:4:4], rule("default", "", "", "", "snmp-default"))}, false, src)
	if d, _ := inv.Get(ctx, "dev3"); d.Unreachable != "" || d.ReadRef != "" || d.SNMP.Ref != "snmp-default" {
		t.Fatalf("snmp only: %+v", d)
	}
}

func TestGaps(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	dns := map[string][]netip.Addr{
		"dev1.example.net": {netip.MustParseAddr("192.0.2.5")},
		"dev2.example.net": {netip.MustParseAddr("192.0.2.6"), netip.MustParseAddr("203.0.113.6")},
	}
	lookup := func(_ context.Context, h string) ([]netip.Addr, error) { return dns[h], nil }
	src := &fake{name: "nb", devs: []Device{{Name: "dev1.example.net", OptedIn: true}, {Name: "dev2.example.net", OptedIn: true}}}

	d := must(New(config.File{Rules: defaultRule}, false, src).Get(ctx, "dev1.example.net"))
	if _, err := Gate(ctx, d, prefixes, lookup); err == nil || !strings.Contains(err.Error(), "resolve_names is off") {
		t.Fatalf("resolve_names off: %v", err)
	}
	inv := New(config.File{Rules: defaultRule, ResolveNames: true}, false, src)
	if a, err := Gate(ctx, must(inv.Get(ctx, "dev1.example.net")), prefixes, lookup); err != nil || a.String() != "192.0.2.5" {
		t.Fatalf("resolve_names on: %v %v", a, err)
	}
	if _, err := Gate(ctx, must(inv.Get(ctx, "dev2.example.net")), prefixes, lookup); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("one resolved address outside: %v", err)
	}
}

func TestAdhoc(t *testing.T) {
	f := config.File{
		ManagementPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		AdhocPrefixes:      []netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")},
		Rules: append([]config.Rule{{Match: config.Match{Kind: "adhoc"}, ReadRef: "adhoc-read"}},
			config.Rule{Match: config.Match{Kind: "default"}, ReadRef: "ssh-read"},
			config.Rule{Match: config.Match{Kind: "device", Value: "192.0.2.130"}, ReadRef: "dev-read"}),
	}
	if _, err := New(f, false).Get(ctx, "192.0.2.130"); err == nil || !strings.Contains(err.Error(), "--allow-adhoc") {
		t.Fatalf("without the flag: %v", err)
	}
	inv := New(f, true)
	if _, err := inv.Get(ctx, "192.0.2.10"); err == nil || !strings.Contains(err.Error(), "adhoc_prefixes") {
		t.Fatalf("outside adhoc_prefixes: %v", err)
	}
	if _, err := inv.Get(ctx, "nope"); err == nil || !strings.Contains(err.Error(), "unknown device") {
		t.Fatalf("a name: %v", err)
	}
	d, err := inv.Get(ctx, "192.0.2.130")
	if err != nil || d.Driver != "generic_ssh" || d.ReadRef != "adhoc-read" || !d.Adhoc || d.Port != 22 || d.Unreachable != "" {
		t.Fatalf("%+v %v", d, err)
	}
	if a, err := Gate(ctx, d, f.ManagementPrefixes, nil); err != nil || a.String() != "192.0.2.130" {
		t.Fatalf("gate: %v %v", a, err)
	}
	f.Rules = f.Rules[1:] // no adhoc rule: default does not apply
	if d := must(New(f, true).Get(ctx, "192.0.2.130")); d.ReadRef != "" || d.Unreachable == "" {
		t.Fatalf("%+v", d)
	}
}

func TestGate(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	dns := map[string][]netip.Addr{
		"in.example.net":    {netip.MustParseAddr("192.0.2.5")},
		"mixed.example.net": {netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("203.0.113.5")},
		"v4in6.example.net": {netip.MustParseAddr("::ffff:192.0.2.6")},
	}
	lookup := func(_ context.Context, h string) ([]netip.Addr, error) { return dns[h], nil }

	for addr, want := range map[string]string{
		"192.0.2.1":         "192.0.2.1",
		"in.example.net":    "192.0.2.5",
		"v4in6.example.net": "192.0.2.6",
		"198.51.100.1":      "outside",
		"mixed.example.net": "outside",
		"none.example.net":  "no address",
	} {
		got, err := Gate(ctx, &Device{Name: "d", Address: addr, OptedIn: true}, prefixes, lookup)
		if s := got.String(); err != nil && !strings.Contains(err.Error(), want) || err == nil && s != want {
			t.Errorf("%s: %v %v, want %q", addr, got, err, want)
		}
	}
	if _, err := Gate(ctx, &Device{Name: "d", Address: "192.0.2.1"}, prefixes, lookup); err == nil {
		t.Error("a device not opted in must be refused")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
