package inventory

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/config"
)

func write(t *testing.T, body string) []config.Source {
	t.Helper()
	p := filepath.Join(t.TempDir(), "devices.yaml")
	os.WriteFile(p, []byte(body), 0o600)
	return []config.Source{{Name: "file", Type: "file", Path: p}}
}

func TestLoad(t *testing.T) {
	inv, err := Load(write(t, `
- {name: dev1, address: 192.0.2.10, platform: cisco_ios, tags: [core]}
- {name: dev2, address: dev2.example.net, port: 2222}
`))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := inv.Get("DEV1")
	if !ok || d.Port != 22 || !d.OptedIn || d.Source != "file" {
		t.Fatalf("%+v", d)
	}
	if inv.Len() != 2 || inv.Health[0].Devices != 2 || !inv.Health[0].OK {
		t.Fatalf("%+v", inv.Health)
	}

	for body, want := range map[string]string{
		"- {name: a, address: 192.0.2.1}\n- {name: A, address: 192.0.2.2}": "duplicate",
		"- {name: a}": "address",
		"- {name: a, address: 192.0.2.1, password: x}": "password",
		"- {name: a, address: 192.0.2.1, port: 70000}": "port",
	} {
		if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
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
		got, err := Gate(context.Background(), &Device{Name: "d", Address: addr, OptedIn: true}, prefixes, lookup)
		if s := got.String(); err != nil && !strings.Contains(err.Error(), want) || err == nil && s != want {
			t.Errorf("%s: %v %v, want %q", addr, got, err, want)
		}
	}
	if _, err := Gate(context.Background(), &Device{Name: "d", Address: "192.0.2.1"}, prefixes, lookup); err == nil {
		t.Error("a device not opted in must be refused")
	}
}
