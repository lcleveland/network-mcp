// Package iosxe applies changes under IOS-XE's Rollback Confirmed Change
// (#10 §1): the device reverts on its own unless configure confirm arrives
// before its timer, so a dropped session or a dead server leaves the old
// config.
//
// shortcut: the replies parsed here come from Cisco's documentation, not a
// lab device (#13); record real transcripts and tighten the parsing then.
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

type Driver struct{}

var _ change.Driver = Driver{}

var (
	archivePath = regexp.MustCompile(`(?m)^archive[ \t]*\r?\n(?:[ \t].*\r?\n)*?[ \t]+path[ \t]+\S`)
	lockOwner   = regexp.MustCompile(`(?mi)^\s*owner pid\s*:`)
	copyDest    = regexp.MustCompile(`\[startup-config\]\?\s*$`)
	backupFile  = regexp.MustCompile(`Backing up current running config to (\S+)`)
)

// Ready needs archive path set (the server never configures it; a platform
// with revert: server uses ServerDriver instead), no revert
// timer pending and no configuration lock.
func (d Driver) Ready(ctx context.Context, c change.Conn, running string) error {
	if !archivePath.MatchString(running) {
		return errors.New("archive path is not configured, so the device cannot revert a change on its own; configure archive path first (the server never does), or set revert: server on its platform for a server-driven revert")
	}
	switch p, err := d.Pending(ctx, c); {
	case err != nil:
		return err
	case p:
		return errors.New("a revert timer is already pending on the device (show archive config rollback timer)")
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

// HasArchive reports whether the running config sets archive path.
func HasArchive(running string) bool { return archivePath.MatchString(running) }

// EnableArchive configures archive path on a device without one, for the
// network_change archive action. It is a plain running-config change: not
// reverted and not saved. It refuses while the configuration is locked; the
// caller checks the path took.
func (Driver) EnableArchive(ctx context.Context, c change.Conn, path string) error {
	out, err := c.Run(ctx, "show configuration lock")
	switch {
	case err != nil:
		return fmt.Errorf("show configuration lock: %w", err)
	case lockOwner.MatchString(out):
		return errors.New("the configuration is locked (show configuration lock)")
	}
	for _, l := range []string{"configure terminal", "archive", "path " + path, "end"} {
		if _, err := run(ctx, c, l); err != nil {
			c.Run(ctx, "end") // in exec mode only an invalid-input reply
			return err
		}
	}
	return nil
}

// Pending treats anything but the documented "none pending" reply as a
// pending timer.
func (Driver) Pending(ctx context.Context, c change.Conn) (bool, error) {
	out, err := c.Run(ctx, "show archive config rollback timer")
	if err != nil {
		return false, fmt.Errorf("show archive config rollback timer: %w", err)
	}
	return !strings.Contains(out, "No Rollback Confirmed Change pending"), nil
}

func (d Driver) Apply(ctx context.Context, c change.Conn, _ string, lines []string, minutes int) (string, error) {
	var backup []string
	for i, l := range slices.Concat([]string{fmt.Sprintf("configure terminal revert timer %d", minutes)}, lines, []string{"end"}) {
		out, err := run(ctx, c, l)
		if err != nil {
			return "", d.revert(ctx, c, err)
		}
		if i == 0 {
			backup = backupFile.FindStringSubmatch(out)
		}
	}
	// the bare command diffs startup against running, which shows unsaved drift and not this change
	if backup == nil {
		return "(diff unavailable: the revert timer did not name its backup file)", nil
	}
	diff, err := c.Run(ctx, "show archive config differences "+backup[1]+" system:running-config")
	if err != nil {
		return "(diff unavailable: " + err.Error() + ")", nil
	}
	return diff, nil
}

// revert leaves config mode and fires the timer now; if that fails too the
// device timer still reverts.
func (Driver) revert(ctx context.Context, c change.Conn, cause error) error {
	c.Run(ctx, "end") // in exec mode only an invalid-input reply
	if _, err := run(ctx, c, "configure revert now"); err != nil {
		return fmt.Errorf("%w; configure revert now failed too, so the device timer reverts the change: %v", cause, err)
	}
	return cause
}

// Confirm needs a pending timer, so a change the timer already reverted is
// never reported confirmed, and checks none is left.
func (d Driver) Confirm(ctx context.Context, c change.Conn, _ string) error {
	switch p, err := d.Pending(ctx, c); {
	case err != nil:
		return err
	case !p:
		return errors.New("no revert timer is pending; the change may have reverted already")
	}
	out, err := c.Run(ctx, "configure confirm")
	if err != nil {
		return err
	}
	switch p, err := d.Pending(ctx, c); {
	case err != nil:
		return err
	case p:
		return fmt.Errorf("the revert timer is still pending after configure confirm: %s", out)
	}
	return nil
}

func (Driver) Rollback(ctx context.Context, c change.Conn, _ string) error {
	_, err := run(ctx, c, "configure revert now")
	return err
}

func (Driver) Save(ctx context.Context, c change.Conn) error {
	out, err := c.Ask(ctx, "copy running-config startup-config", copyDest)
	if err == nil && !strings.Contains(out, "[OK]") {
		err = errors.New(out)
	}
	return err
}

// Forget has nothing to drop: the timer leaves no marker.
func (Driver) Forget(context.Context, change.Conn, string) error { return nil }

func (Driver) DeviceReverts() bool { return true }

func (Driver) Warning(string) string { return "" }

// run fails on any line of the reply that starts with %, not only the
// driver's known failure strings.
func run(ctx context.Context, c change.Conn, cmd string) (string, error) {
	out, err := c.Run(ctx, cmd)
	if err != nil {
		return out, fmt.Errorf("%s: %w", cmd, err)
	}
	for l := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "%") {
			return out, fmt.Errorf("%s: %s", cmd, strings.TrimSpace(out))
		}
	}
	return out, nil
}
