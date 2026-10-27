package inventory

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/config"
)

func TestNetBox(t *testing.T) {
	var auths, queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/nb/api/dcim/devices/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		auths, queries = append(auths, r.Header.Get("Authorization")), append(queries, r.URL.RawQuery)
		if r.URL.Query().Get("offset") == "" {
			// next points at another host: only its path and query may be used
			fmt.Fprint(w, `{"next": "http://other.example.net/nb/api/dcim/devices/?offset=2&tag=mcp", "results": [
				{"id": 1, "name": "dev1", "platform": {"slug": "cisco-nx-os"}, "primary_ip4": {"address": "192.0.2.1/24"},
				 "primary_ip6": {"address": "2001:db8::1/64"}, "oob_ip": {"address": "192.0.2.201/24"}, "tags": [{"slug": "mcp"}]},
				{"id": 2, "name": "dev2", "platform": null, "primary_ip4": null, "primary_ip6": {"address": "2001:db8::2/64"}, "tags": [{"slug": "mcp"}, {"slug": "core"}]}]}`)
			return
		}
		// a server that ignored the tag filter returns an untagged device
		fmt.Fprint(w, `{"next": null, "results": [
			{"id": 3, "name": "dev3", "primary_ip4": {"address": "192.0.2.3/24"}, "tags": [{"slug": "other"}]},
			{"id": 4, "name": null, "tags": [{"slug": "mcp"}]}]}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	src := config.Source{Name: "nb", Type: "netbox", URL: srv.URL + "/nb", TokenRef: "nb-token", OptInTag: "mcp", AddressOrder: config.AddressFields}
	for tok, want := range map[string]string{"nbt_abc.secretpart123": "Bearer nbt_abc.secretpart123", "0123456789abcdef": "Token 0123456789abcdef"} {
		os.WriteFile(filepath.Join(dir, "nb-token"), []byte(`{"token":"`+tok+`"}`), 0o600)
		auths = nil
		devs, err := newNetBox(src, dir).List(ctx)
		if err != nil || len(devs) != 3 || len(auths) != 2 || auths[0] != want || auths[1] != want {
			t.Fatalf("%v %v %q", devs, err, auths)
		}
	}
	if !strings.Contains(queries[0], "tag=mcp") || !strings.Contains(queries[0], "fields=id%2Cname%2Cplatform") {
		t.Errorf("query: %s", queries[0])
	}

	inv := New(config.File{Rules: defaultRule}, false, newNetBox(src, dir))
	d := must(inv.Get(ctx, "dev1"))
	if d.Address != "192.0.2.1" || d.Platform != "cisco-nx-os" || d.Driver != "nxos" || !d.OptedIn || d.Provenance["address"] != "nb" {
		t.Fatalf("dev1: %+v", d)
	}
	if d := must(inv.Get(ctx, "dev2")); d.Address != "2001:db8::2" || d.Driver != "generic_ssh" || strings.Join(d.Tags, ",") != "mcp,core" {
		t.Fatalf("dev2: %+v", d)
	}
	if d := must(inv.Get(ctx, "dev3")); d.OptedIn {
		t.Fatal("dev3 lacks the opt-in tag but is opted in")
	}
	if _, err := Gate(ctx, must(inv.Get(ctx, "dev3")), nil, nil); err == nil || !strings.Contains(err.Error(), "not opted in") {
		t.Fatalf("dev3: %v", err)
	}

	src.AddressOrder = []string{"oob_ip", "primary_ip4"}
	if d := must(New(config.File{Rules: defaultRule}, false, newNetBox(src, dir)).Get(ctx, "dev1")); d.Address != "192.0.2.201" {
		t.Fatalf("address_order: %+v", d)
	}
}

func TestNetBoxErrors(t *testing.T) {
	const tok = "nbt_abc.secretpart123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/denied/api/dcim/devices/":
			http.Error(w, `{"detail": "Invalid token `+tok+`"}`, http.StatusForbidden)
		case "/redirect/api/dcim/devices/":
			http.Redirect(w, r, "http://other.example.net/", http.StatusFound)
		default:
			fmt.Fprint(w, `not json `+tok)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nb-token"), []byte(`{"token":"`+tok+`"}`), 0o600)

	for _, path := range []string{"/denied", "/redirect", "/junk"} {
		src := config.Source{Name: "nb", URL: srv.URL + path, TokenRef: "nb-token", OptInTag: "mcp"}
		inv := New(config.File{}, false, newNetBox(src, dir))
		h := inv.Health(ctx)
		if h[0].OK || h[0].Error == "" || strings.Contains(h[0].Error, "secretpart") {
			t.Errorf("%s: %+v", path, h)
		}
	}
	src := config.Source{Name: "nb", URL: srv.URL, TokenRef: "missing", OptInTag: "mcp"}
	if _, err := newNetBox(src, dir).List(ctx); err == nil {
		t.Error("a missing token ref was accepted")
	}
}

func TestManagementPrefixes(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/api/ipam/prefixes/") {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		queries = append(queries, r.URL.RawQuery)
		switch strings.TrimSuffix(r.URL.Path, "/api/ipam/prefixes/") {
		case "/ok":
			// the last two do not match the selector: a NetBox that ignored the filter
			fmt.Fprint(w, `{"next": null, "results": [
				{"prefix": "192.0.2.0/24", "role": {"slug": "management"}, "tags": [{"slug": "mgmt"}]},
				{"prefix": "2001:db8::/64", "role": {"slug": "management"}, "tags": [{"slug": "mgmt"}, {"slug": "x"}]},
				{"prefix": "198.51.100.0/24", "role": {"slug": "data"}, "tags": [{"slug": "mgmt"}]},
				{"prefix": "203.0.113.0/24", "role": null, "tags": []}]}`)
		case "/down":
			http.Error(w, "maintenance", http.StatusServiceUnavailable)
		case "/denied":
			http.Error(w, "no", http.StatusForbidden)
		case "/empty":
			fmt.Fprint(w, `{"next": null, "results": []}`)
		case "/bad":
			fmt.Fprint(w, `{"next": null, "results": [{"prefix": "nope", "tags": [{"slug": "mgmt"}]}]}`)
		}
	}))
	defer srv.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nb-token"), []byte(`{"token":"0123456789abcdef"}`), 0o600)
	file := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cfg := func(url string, sel config.PrefixSelector, mgmt, adhoc []netip.Prefix) *config.Config {
		src := config.Source{Name: "nb", Type: "netbox", URL: url, TokenRef: "nb-token", OptInTag: "mcp", ManagementPrefixes: &sel}
		return &config.Config{CredentialsDir: dir, File: config.File{ManagementPrefixes: mgmt, AdhocPrefixes: adhoc, Sources: []config.Source{src}}}
	}

	// NetBox wins over the file list, by tag or by role
	for sel, want := range map[config.PrefixSelector]string{{Tag: "mgmt"}: "[192.0.2.0/24 2001:db8::/64 198.51.100.0/24]", {Role: "management"}: "[192.0.2.0/24 2001:db8::/64]"} {
		c := cfg(srv.URL+"/ok", sel, file, nil)
		if fb, err := ManagementPrefixes(ctx, c); fb != nil || err != nil || fmt.Sprint(c.File.ManagementPrefixes) != want {
			t.Errorf("%+v: %v %v %v", sel, c.File.ManagementPrefixes, fb, err)
		}
	}
	if q := queries[0] + queries[1]; !strings.Contains(q, "tag=mgmt") || !strings.Contains(q, "role=management") {
		t.Errorf("queries: %q", queries)
	}
	c := cfg(srv.URL+"/ok", config.PrefixSelector{Role: "management"}, nil, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/25")})
	if _, err := ManagementPrefixes(ctx, c); err == nil || !strings.Contains(err.Error(), "adhoc_prefixes[0]") {
		t.Errorf("adhoc outside the NetBox prefixes: %v", err)
	}

	// an outage falls back to the file list, and refuses startup without one
	for _, url := range []string{srv.URL + "/down", closed.URL} {
		c := cfg(url, config.PrefixSelector{Tag: "mgmt"}, file, nil)
		if fb, err := ManagementPrefixes(ctx, c); fb == nil || err != nil || fmt.Sprint(c.File.ManagementPrefixes) != "[10.0.0.0/8]" {
			t.Errorf("%s: %v %v", url, fb, err)
		}
		if _, err := ManagementPrefixes(ctx, cfg(url, config.PrefixSelector{Tag: "mgmt"}, nil, nil)); err == nil {
			t.Errorf("%s without a file list started", url)
		}
	}
	// misconfiguration never falls back, and names no prefix
	for path, want := range map[string]string{"/denied": "403", "/empty": "no IPAM prefix", "/bad": "result 0 is malformed"} {
		fb, err := ManagementPrefixes(ctx, cfg(srv.URL+path, config.PrefixSelector{Tag: "mgmt"}, file, nil))
		if fb != nil || err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "nope") {
			t.Errorf("%s: %v %v", path, fb, err)
		}
	}
	if fb, err := ManagementPrefixes(ctx, &config.Config{File: config.File{ManagementPrefixes: file}}); fb != nil || err != nil {
		t.Errorf("no prefix source: %v %v", fb, err)
	}
}
