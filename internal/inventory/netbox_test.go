package inventory

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
