package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/creds"
)

// netBox reads opted-in devices from NetBox. It only ever sends GET.
type netBox struct {
	cfg     config.Source
	credDir string
	hc      *http.Client
}

func newNetBox(s config.Source, credDir string) *netBox {
	return &netBox{cfg: s, credDir: credDir, hc: &http.Client{
		Timeout: 30 * time.Second,
		// a redirect could carry the token elsewhere or downgrade the scheme
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (n *netBox) Name() string { return n.cfg.Name }

type nbIP struct {
	Address string `json:"address"`
}

type nbDevice struct {
	Name     *string `json:"name"`
	Platform *struct {
		Slug string `json:"slug"`
	} `json:"platform"`
	PrimaryIP4 *nbIP `json:"primary_ip4"`
	PrimaryIP6 *nbIP `json:"primary_ip6"`
	OOBIP      *nbIP `json:"oob_ip"`
	Tags       []struct {
		Slug string `json:"slug"`
	} `json:"tags"`
}

func (n *netBox) List(ctx context.Context) ([]Device, error) {
	q := url.Values{}
	for k, v := range n.cfg.Filters {
		q.Set(k, v)
	}
	q.Set("tag", n.cfg.OptInTag)
	q.Set("fields", "id,name,platform,primary_ip4,primary_ip6,oob_ip,tags")
	rs, err := getAll[nbDevice](ctx, n, "api/dcim/devices/", q)
	if err != nil {
		return nil, err
	}
	var devs []Device
	for _, r := range rs {
		if r.Name != nil && *r.Name != "" {
			devs = append(devs, r.device(n.cfg))
		}
	}
	return devs, nil
}

// prefixes returns the IPAM prefixes the source's management_prefixes
// selector picks. Errors name an index, never a prefix.
func (n *netBox) prefixes(ctx context.Context) ([]netip.Prefix, error) {
	sel := n.cfg.ManagementPrefixes
	q := url.Values{"fields": {"prefix,role,tags"}}
	if sel.Tag != "" {
		q.Set("tag", sel.Tag)
	} else {
		q.Set("role", sel.Role)
	}
	type slug struct {
		Slug string `json:"slug"`
	}
	rs, err := getAll[struct {
		Prefix string `json:"prefix"`
		Role   *slug  `json:"role"`
		Tags   []slug `json:"tags"`
	}](ctx, n, "api/ipam/prefixes/", q)
	if err != nil {
		return nil, err
	}
	var ps []netip.Prefix
	for i, r := range rs {
		// NetBox ignores a filter it does not know, so the selector is checked here too
		if sel.Tag != "" && !slices.Contains(r.Tags, slug{sel.Tag}) || sel.Role != "" && (r.Role == nil || *r.Role != slug{sel.Role}) {
			continue
		}
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			return nil, fmt.Errorf("netbox: management prefix result %d is malformed", i)
		}
		ps = append(ps, p.Masked())
	}
	if len(ps) == 0 {
		return nil, errors.New("netbox: no IPAM prefix matches management_prefixes")
	}
	return ps, nil
}

// errUnreachable marks a NetBox outage (no connection, timeout, 5xx), as
// opposed to a refusal or bad data from a NetBox that answered.
var errUnreachable = errors.New("netbox unreachable")

func (n *netBox) auth() (string, error) {
	tok, err := creds.Token(n.credDir, n.cfg.TokenRef)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(tok, "nbt_") {
		return "Bearer " + tok, nil
	}
	return "Token " + tok, nil
}

// getAll GETs every page of a NetBox list endpoint.
func getAll[T any](ctx context.Context, n *netBox, path string, q url.Values) ([]T, error) {
	auth, err := n.auth()
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(n.cfg.URL)
	if err != nil {
		return nil, err
	}
	q.Set("limit", "1000")
	u := base.JoinPath(path)
	u.RawQuery = q.Encode()
	var all []T
	for u != nil {
		var page struct {
			Next    string `json:"next"`
			Results []T    `json:"results"`
		}
		if err := n.get(ctx, u, auth, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Results...)
		u = nil
		if page.Next != "" {
			nu, err := url.Parse(page.Next)
			if err != nil {
				return nil, fmt.Errorf("netbox: bad next link: %w", err)
			}
			// only the path and query are taken, so the token stays on the configured host
			u = base.JoinPath()
			u.Path, u.RawPath, u.RawQuery = nu.Path, nu.RawPath, nu.RawQuery
		}
	}
	return all, nil
}

func (n *netBox) get(ctx context.Context, u *url.URL, auth string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	resp, err := n.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", errUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("%w: GET %s: %s", errUnreachable, u.Path, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("netbox: GET %s: %s", u.Path, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v); err != nil {
		return fmt.Errorf("netbox: GET %s: decoding: %w", u.Path, err)
	}
	return nil
}

// device maps a NetBox object. The opt-in tag is checked here because NetBox
// silently ignores a filter it does not know.
func (r nbDevice) device(s config.Source) Device {
	d := Device{Name: *r.Name}
	if r.Platform != nil {
		d.Platform = r.Platform.Slug
	}
	ips := map[string]*nbIP{"primary_ip4": r.PrimaryIP4, "primary_ip6": r.PrimaryIP6, "oob_ip": r.OOBIP}
	for _, f := range s.AddressOrder {
		if ip := ips[f]; ip != nil && ip.Address != "" {
			d.Address, _, _ = strings.Cut(ip.Address, "/")
			break
		}
	}
	for _, t := range r.Tags {
		d.Tags = append(d.Tags, t.Slug)
		d.OptedIn = d.OptedIn || t.Slug == s.OptInTag
	}
	return d
}
