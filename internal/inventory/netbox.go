package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	tok, err := creds.Token(n.credDir, n.cfg.TokenRef)
	if err != nil {
		return nil, err
	}
	auth := "Token " + tok
	if strings.HasPrefix(tok, "nbt_") {
		auth = "Bearer " + tok
	}
	base, err := url.Parse(n.cfg.URL)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	for k, v := range n.cfg.Filters {
		q.Set(k, v)
	}
	q.Set("tag", n.cfg.OptInTag)
	q.Set("fields", "id,name,platform,primary_ip4,primary_ip6,oob_ip,tags")
	q.Set("limit", "1000")
	u := base.JoinPath("api/dcim/devices/")
	u.RawQuery = q.Encode()

	var devs []Device
	for u != nil {
		var page struct {
			Next    string     `json:"next"`
			Results []nbDevice `json:"results"`
		}
		if err := n.get(ctx, u, auth, &page); err != nil {
			return nil, err
		}
		for _, r := range page.Results {
			if r.Name != nil && *r.Name != "" {
				devs = append(devs, r.device(n.cfg))
			}
		}
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
	return devs, nil
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
		return err
	}
	defer resp.Body.Close()
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
