// Package export writes fetched configs to named destinations. The caller
// redacts; a sink only stores what it is given, at <device>/<kind>.<ext>.
package export

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/lcleveland/network-mcp/internal/config"
)

type Artifact struct {
	Device, Kind, Ext string
	Body              []byte
	SHA256            string
	FetchedAt         time.Time
	Redacted          bool
}

// Receipt is one artifact's outcome. Ref is sink-specific (a path, a commit).
type Receipt struct {
	Destination string
	Changed     bool
	Ref         string
}

// Sink stores one batch per export call and returns a receipt per artifact,
// in order.
type Sink interface {
	Put(ctx context.Context, a []Artifact, reason string) ([]Receipt, error)
}

// New builds the sink for a validated destination.
func New(name string, d config.Destination) (Sink, error) {
	switch d.Type {
	case "dir":
		return Dir{Name: name, Root: d.Path}, nil
	}
	return nil, fmt.Errorf("destination %s: unknown type %q", name, d.Type)
}

// NewArtifact hashes body.
func NewArtifact(device, kind string, body []byte, redacted bool) Artifact {
	h := sha256.Sum256(body)
	return Artifact{Device: device, Kind: kind, Ext: "txt", Body: body, SHA256: hex.EncodeToString(h[:]), FetchedAt: time.Now().UTC(), Redacted: redacted}
}

// ValidName refuses a path element that could escape the root, hide, or put
// an address in a path.
func ValidName(s string) error {
	_, ipErr := netip.ParseAddr(s)
	switch {
	case s == "" || strings.HasPrefix(s, ".") || strings.ContainsAny(s, `/\`) || strings.Contains(s, ".."):
		return fmt.Errorf("name %q is not a safe path element", s)
	case strings.ContainsFunc(s, unicode.IsControl):
		return fmt.Errorf("name %q contains a control character", s)
	case ipErr == nil:
		return fmt.Errorf("name %q is an address; export needs an inventory name", s)
	}
	return nil
}

// Rel is an artifact's path under the destination root.
func (a Artifact) Rel() (string, error) {
	for _, s := range []string{a.Device, a.Kind, a.Kind + "." + a.Ext} {
		if err := ValidName(s); err != nil {
			return "", err
		}
	}
	return path.Join(a.Device, a.Kind+"."+a.Ext), nil
}

// Dir writes each artifact atomically under Root, confined by os.Root.
type Dir struct{ Name, Root string }

func (d Dir) Put(ctx context.Context, as []Artifact, _ string) ([]Receipt, error) {
	if err := os.MkdirAll(d.Root, 0o750); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(d.Root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var rs []Receipt
	for _, a := range as {
		if err := ctx.Err(); err != nil {
			return rs, err
		}
		rel, err := a.Rel()
		if err != nil {
			return rs, err
		}
		changed, err := write(root, rel, a)
		if err != nil {
			return rs, fmt.Errorf("%s: %w", rel, err)
		}
		rs = append(rs, Receipt{Destination: d.Name, Changed: changed, Ref: rel})
	}
	return rs, nil
}

// write skips an identical file; otherwise temp file, fsync, rename, so a
// reader never sees half a config.
func write(root *os.Root, rel string, a Artifact) (bool, error) {
	if old, err := root.ReadFile(rel); err == nil {
		h := sha256.Sum256(old)
		if hex.EncodeToString(h[:]) == a.SHA256 {
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := root.MkdirAll(a.Device, 0o750); err != nil {
		return false, err
	}
	tmp := path.Join(a.Device, "."+a.Kind+".tmp-"+rand.Text())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return false, err
	}
	_, err = f.Write(a.Body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, rel)
	}
	if err != nil {
		root.Remove(tmp)
		return false, err
	}
	if dir, err := root.Open(a.Device); err == nil {
		dir.Sync() // persist the rename; best effort
		dir.Close()
	}
	return true, nil
}
