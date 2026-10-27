package tools

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/lcleveland/network-mcp/internal/audit"
	"github.com/lcleveland/network-mcp/internal/change/hash"
	"github.com/lcleveland/network-mcp/internal/change/iosxe"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshcli"
)

// archive configures archive / path on an IOS-XE device whose platform sets
// archive_path, so its changes can use the device's own revert timer. It is
// a one-off running-config change, not reverted and not saved; like a
// confirmed change, its post-hash is what a later save may write. A plan
// made before it no longer matches the running config.
func (d Deps) archive(ctx context.Context, sid, client string, in ChangeInput) (ChangeOutput, error) {
	ev := audit.Event{Event: "archive", MCPSession: sid, Client: client, Reason: cleanReason(in.Reason), Device: in.Device}
	if err := checkReason(in.Reason); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	g, err := d.gate(ctx, in.Device)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	ev.Device, ev.Address, ev.Platform, ev.CredRef = g.dev.Name, g.addr.String(), g.plat.Driver, g.dev.WriteRef
	ev.HostKey, _ = sshcli.HostKey(d.Config.KnownHosts, g.addr, g.dev.Port)
	switch {
	case g.plat.Driver != platform.IOSXE || g.dev.Adhoc || g.dev.WriteRef == "":
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("%s is not an IOS-XE device with a write_ref", g.dev.Name))
	case g.plat.ArchivePath == "":
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("the platform of %s sets no archive_path, so the server may not configure archive on it", g.dev.Name))
	}
	// holds the device against an apply; counts toward no limit
	if err := d.Changes.Reserve(g.dev.Name, math.MaxInt); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	defer d.Changes.Release(g.dev.Name)
	g.ref = g.dev.WriteRef
	conn, err := d.dial(ctx, g, "")
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	defer conn.Close()
	raw, err := conn.Run(ctx, g.plat.Config.Running)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("reading the running config: %w", err))
	}
	ev.PreHash = hash.Sum(raw)
	out := ChangeOutput{Device: g.dev.Name, PreHash: ev.PreHash}
	if iosxe.HasArchive(raw) {
		ev.Outcome = "unchanged"
		d.audit(ev)
		out.Outcome = "already_configured"
		return out, nil
	}
	ev.Commands = []string{"archive", "path " + g.plat.ArchivePath}
	if err := d.begin(ev); err != nil {
		return ChangeOutput{}, err
	}
	if err := (iosxe.Driver{}).EnableArchive(ctx, conn, g.plat.ArchivePath); err != nil {
		return d.failed(ev, out, err)
	}
	raw, err = conn.Run(ctx, g.plat.Config.Running)
	switch {
	case err != nil:
		return d.failed(ev, out, fmt.Errorf("reading the running config: %w", err))
	case !iosxe.HasArchive(raw):
		return d.failed(ev, out, errors.New("archive path is still not in the running config"))
	}
	ev.PostHash, ev.Outcome = hash.Sum(raw), "ok"
	d.audit(ev)
	// a later save (--allow-save) may write exactly this config, nothing else
	d.Changes.Record(g.dev.Name, ev.PostHash)
	out.PostHash, out.Outcome = ev.PostHash, "archive_configured"
	return out, nil
}
