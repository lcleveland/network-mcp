// Package nxos applies changes under an NX-OS checkpoint with a
// server-driven rollback (#10 §1, user ruling). NX-OS has no timed revert
// for a set of lines, so the server rolls back at the deadline; if the
// server stops first, or the change cuts it off, the change stays applied
// and the checkpoint network-mcp-<change_id> marks it.
//
// shortcut: the replies parsed here come from Cisco's documentation, not a
// lab device (#13); record real transcripts and tighten the parsing then.
package nxos

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/lcleveland/network-mcp/internal/change"
)

// Prefix names the checkpoint of every change; one left on a device is a
// change nobody confirmed or rolled back.
const Prefix = "network-mcp-"

// Warning is returned by every NX-OS apply; %s is the change_id.
const Warning = "NX-OS revert is server-driven. If the server stops before the deadline, or this change cuts the server off " +
	"from the device, the change stays applied until an operator runs `rollback running-config checkpoint " + Prefix + "%s`."

var marker = regexp.MustCompile(Prefix + `[0-9A-Za-z_.-]+`)

type Driver struct{}

var _ change.Driver = Driver{}

// Checkpoints lists the network-mcp-* checkpoints on the device. Any match
// in the summary counts, so a format change over-reports rather than hides.
func Checkpoints(ctx context.Context, c change.Conn) ([]string, error) {
	out, err := run(ctx, c, "show checkpoint summary")
	if err != nil {
		return nil, err
	}
	names := marker.FindAllString(out, -1)
	slices.Sort(names)
	return slices.Compact(names), nil
}

// Ready refuses while any network-mcp-* checkpoint is on the device.
func (Driver) Ready(ctx context.Context, c change.Conn, _ string) error {
	names, err := Checkpoints(ctx, c)
	if err == nil && len(names) > 0 {
		err = fmt.Errorf("checkpoint %s is on the device: a change nobody confirmed or rolled back; an operator must check it and run rollback running-config checkpoint <name> or no checkpoint <name>", strings.Join(names, ", "))
	}
	return err
}

func (Driver) Pending(ctx context.Context, c change.Conn) (bool, error) {
	names, err := Checkpoints(ctx, c)
	return len(names) > 0, err
}

func (d Driver) Apply(ctx context.Context, c change.Conn, id string, lines []string, _ int) (string, error) {
	if _, err := run(ctx, c, "checkpoint "+Prefix+id); err != nil {
		return "", err // nothing applied
	}
	for _, l := range slices.Concat([]string{"configure terminal"}, lines, []string{"end"}) {
		if _, err := run(ctx, c, l); err != nil {
			c.Run(ctx, "end") // in exec mode only an invalid-command reply
			if rerr := d.Rollback(ctx, c, id); rerr != nil {
				return "", fmt.Errorf("%w; the rollback failed too, so the change may stay applied: %v", err, rerr)
			}
			return "", err
		}
	}
	return c.Run(ctx, "show diff rollback-patch checkpoint "+Prefix+id+" running-config")
}

// Confirm keeps the change by deleting its checkpoint.
func (Driver) Confirm(ctx context.Context, c change.Conn, id string) error {
	_, err := run(ctx, c, "no checkpoint "+Prefix+id)
	return err
}

// Rollback restores the checkpoint, all or nothing; the caller checks the hash.
func (Driver) Rollback(ctx context.Context, c change.Conn, id string) error {
	_, err := run(ctx, c, "rollback running-config checkpoint "+Prefix+id+" atomic")
	return err
}

func (d Driver) Forget(ctx context.Context, c change.Conn, id string) error {
	return d.Confirm(ctx, c, id)
}

func (Driver) DeviceReverts() bool { return false }

func (Driver) Save(ctx context.Context, c change.Conn) error {
	out, err := run(ctx, c, "copy running-config startup-config")
	if err == nil && !strings.Contains(out, "Copy complete") {
		err = errors.New(out)
	}
	return err
}

// run fails on any reply line starting with % or ERROR, not only the
// driver's known failure strings.
func run(ctx context.Context, c change.Conn, cmd string) (string, error) {
	out, err := c.Run(ctx, cmd)
	if err != nil {
		return out, fmt.Errorf("%s: %w", cmd, err)
	}
	for l := range strings.SplitSeq(out, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "%") || strings.HasPrefix(strings.ToUpper(l), "ERROR") {
			return out, fmt.Errorf("%s: %s", cmd, strings.TrimSpace(out))
		}
	}
	return out, nil
}
