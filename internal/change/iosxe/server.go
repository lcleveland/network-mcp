package iosxe

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/lcleveland/network-mcp/internal/change"
)

// Prefix names the running-config snapshot of every server-reverted change;
// one left on flash is a change nobody confirmed or rolled back.
const Prefix = "network-mcp-"

// ServerWarning is returned by every server-reverted IOS-XE apply; %[1]s is
// the change_id.
const ServerWarning = "This IOS-XE device has no archive, so revert is server-driven. If the server stops before the deadline, or this " +
	"change cuts the server off from the device, the change stays applied until an operator runs `configure replace flash:" +
	Prefix + "%[1]s.cfg force` and then `delete /force flash:" + Prefix + "%[1]s.cfg`."

var (
	snapshot = regexp.MustCompile(Prefix + `[0-9A-Za-z_.-]+\.cfg`)
	destFile = regexp.MustCompile(`Destination filename \[[^\]\n]*\]\?\s*$`)
)

// ServerDriver applies IOS-XE changes on a device without archive path
// (platforms.<value>.revert: server). Before the lines it copies the running
// config to flash:network-mcp-<change_id>.cfg; on error, rollback or an
// unconfirmed deadline the server restores it with configure replace, like
// NX-OS's checkpoint. If the server stops first, the change stays applied
// and the snapshot marks it.
//
// shortcut: the copy, configure replace and dir replies come from Cisco's
// documentation, not a lab device (#13); record real transcripts then.
type ServerDriver struct{ Driver }

var _ change.Driver = ServerDriver{}

func file(id string) string { return "flash:" + Prefix + id + ".cfg" }

// Snapshots lists the network-mcp-*.cfg files on flash. Any match in the
// listing counts, so a format change over-reports rather than hides.
func Snapshots(ctx context.Context, c change.Conn) ([]string, error) {
	out, err := run(ctx, c, "dir flash:")
	if err != nil {
		return nil, err
	}
	names := snapshot.FindAllString(out, -1)
	slices.Sort(names)
	return slices.Compact(names), nil
}

// Ready refuses while a snapshot is on flash or the configuration is
// locked; archive is not needed.
func (ServerDriver) Ready(ctx context.Context, c change.Conn, _ string) error {
	names, err := Snapshots(ctx, c)
	switch {
	case err != nil:
		return err
	case len(names) > 0:
		return fmt.Errorf("%s is on flash: a change nobody confirmed or rolled back; an operator must recover it by hand (README: Recovering a leftover snapshot)", strings.Join(names, ", "))
	}
	out, err := c.Run(ctx, "show configuration lock")
	switch {
	case err != nil:
		return fmt.Errorf("show configuration lock: %w", err)
	case lockOwner.MatchString(out):
		return errors.New("the configuration is locked (show configuration lock)")
	}
	return nil
}

func (ServerDriver) Pending(ctx context.Context, c change.Conn) (bool, error) {
	names, err := Snapshots(ctx, c)
	return len(names) > 0, err
}

func (d ServerDriver) Apply(ctx context.Context, c change.Conn, id string, lines []string, _ int) (string, error) {
	out, err := c.Ask(ctx, "copy running-config "+file(id), destFile)
	if err == nil && (!strings.Contains(out, "bytes copied") || strings.Contains(out, "%")) {
		err = fmt.Errorf("copy running-config %s: %s", file(id), strings.TrimSpace(out))
	}
	if err != nil {
		return "", err // nothing applied
	}
	for _, l := range slices.Concat([]string{"configure terminal"}, lines, []string{"end"}) {
		if _, err := run(ctx, c, l); err != nil {
			c.Run(ctx, "end") // in exec mode only an invalid-input reply
			if rerr := d.Rollback(ctx, c, id); rerr != nil {
				return "", fmt.Errorf("%w; the rollback failed too, so the change may stay applied: %v", err, rerr)
			}
			return "", err
		}
	}
	// the diff is informational: failing to read it must not fail a change already made
	diff, err := c.Run(ctx, "show archive config differences "+file(id)+" system:running-config")
	if err != nil {
		return "(diff unavailable: " + err.Error() + ")", nil
	}
	return diff, nil
}

// Confirm keeps the change by deleting its snapshot.
func (ServerDriver) Confirm(ctx context.Context, c change.Conn, id string) error {
	_, err := run(ctx, c, "delete /force "+file(id))
	return err
}

// Rollback replaces the running config with the snapshot; the caller checks
// the hash and then Forgets it.
func (ServerDriver) Rollback(ctx context.Context, c change.Conn, id string) error {
	_, err := run(ctx, c, "configure replace "+file(id)+" force")
	return err
}

func (d ServerDriver) Forget(ctx context.Context, c change.Conn, id string) error {
	return d.Confirm(ctx, c, id)
}

func (ServerDriver) DeviceReverts() bool { return false }

func (ServerDriver) Warning(id string) string { return fmt.Sprintf(ServerWarning, id) }
