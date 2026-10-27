package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/lcleveland/network-mcp/internal/audit"
	"github.com/lcleveland/network-mcp/internal/change"
	"github.com/lcleveland/network-mcp/internal/change/hash"
	"github.com/lcleveland/network-mcp/internal/change/iosxe"
	"github.com/lcleveland/network-mcp/internal/change/nxos"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshcli"
)

// Revert window bounds, compiled in (#10 §4).
const (
	MinRevert     = 2
	MaxRevert     = 15
	DefaultRevert = 5
)

// deadlineGrace lets the device timer fire before the deadline check dials.
// shortcut: how long IOS-XE takes to revert is unmeasured; tune on hardware.
const deadlineGrace = time.Minute

// drivers are the platforms that can apply a change.
var drivers = map[string]change.Driver{platform.IOSXE: iosxe.Driver{}, platform.NXOS: nxos.Driver{}}

// changeDriver is the change driver for a plan or platform: IOS-XE with
// revert: server gets the flash-snapshot driver. nil means none.
func changeDriver(driver, revert string) change.Driver {
	if driver == platform.IOSXE && revert == platform.RevertServer {
		return iosxe.ServerDriver{}
	}
	return drivers[driver]
}

// grace is how long after its deadline a change is checked: the device
// timer's head start, or none when the server reverts it.
func grace(drv change.Driver) time.Duration {
	if drv.DeviceReverts() {
		return deadlineGrace
	}
	return 0
}

// writeEvent is an audit line for a plan's device; c adds the change fields.
func writeEvent(event, sid, client, reason string, p change.Plan, c *change.Change) audit.Event {
	cmds, _ := redactLines(p.Lines)
	ev := audit.Event{Event: event, MCPSession: sid, Client: client, Reason: cleanReason(reason),
		Device: p.Device, Address: p.Address, Platform: p.Driver, HostKey: p.HostKey, CredRef: p.WriteRef,
		Username: p.Username, PlanID: p.ID, Commands: cmds, PreHash: p.PreHash}
	if c != nil {
		ev.ChangeID, ev.PostHash, ev.Revert, ev.Deadline = c.ID, c.PostHash, c.Minutes, c.Deadline.UTC().Format(time.RFC3339)
	}
	return ev
}

// failed audits a device-side failure and returns it as device_error.
func (d Deps) failed(ev audit.Event, out ChangeOutput, err error) (ChangeOutput, error) {
	ev.Outcome, ev.Error = "device_error", output.Cap(output.Sanitize(err.Error()), output.LongCap)
	d.audit(ev)
	out.Outcome = "device_error"
	out.DeviceError, out.Redactions, out.Untrusted = deviceError(err)
	return out, nil
}

func runningHash(ctx context.Context, c change.Conn, g *gated) (string, error) {
	raw, err := c.Run(ctx, g.plat.Config.Running)
	if err != nil {
		return "", fmt.Errorf("reading the running config: %w", err)
	}
	return hash.Sum(raw), nil
}

// apply consumes a plan and applies it under the device's revert timer.
func (d Deps) apply(ctx context.Context, sid, client string, in ChangeInput) (ChangeOutput, error) {
	ev := audit.Event{Event: "apply", MCPSession: sid, Client: client, Reason: cleanReason(in.Reason), PlanID: in.PlanID}
	minutes := cmp.Or(in.RevertMinutes, DefaultRevert)
	if err := checkReason(in.Reason); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	if minutes < MinRevert || minutes > MaxRevert {
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("revert_minutes must be %d to %d", MinRevert, MaxRevert))
	}
	// the plan is used up by any apply, even one refused below
	var g *gated
	var gerr error
	hk := ""
	plans := d.Changes.Plans()
	if i := slices.IndexFunc(plans, func(p change.Plan) bool { return p.ID == in.PlanID && p.Session == sid }); i >= 0 {
		if g, gerr = d.target(ctx, plans[i]); gerr == nil {
			hk = plans[i].HostKey
		}
	}
	p, err := d.Changes.Take(in.PlanID, sid, hk)
	if p.ID != "" {
		ev = writeEvent("apply", sid, client, in.Reason, p, nil)
	}
	if err = cmp.Or(gerr, err); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	drv := changeDriver(p.Driver, p.Revert)
	if drv == nil {
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("applying changes to %s devices is not supported yet", p.Driver))
	}
	if err := d.Changes.Reserve(p.Device, d.Config.MaxPendingChanges); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	committed := false
	defer func() {
		if !committed {
			d.Changes.Release(p.Device)
		}
	}()
	conn, err := d.dial(ctx, g, p.Username)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	defer func() {
		if !committed {
			conn.Close()
		}
	}()
	running, err := conn.Run(ctx, g.plat.Config.Running)
	switch {
	case err != nil:
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("reading the running config: %w", err))
	case hash.Sum(running) != p.PreHash:
		return ChangeOutput{}, d.refuse(ev, "refused", errors.New("the running config changed since the plan; plan again"))
	}
	if err := drv.Ready(ctx, conn, running); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}

	c := &change.Change{ID: change.NewID(), Plan: p, Minutes: minutes, Deadline: d.Changes.Now().Add(time.Duration(minutes) * time.Minute), Conn: conn}
	ev = writeEvent("apply", sid, client, in.Reason, p, c)
	if err := d.begin(ev); err != nil {
		return ChangeOutput{}, err
	}
	out := ChangeOutput{Device: p.Device, ChangeID: c.ID, PreHash: p.PreHash}
	diff, err := drv.Apply(ctx, conn, c.ID, p.Lines, minutes)
	if err != nil {
		ev.PostHash, _ = runningHash(ctx, conn, g) // shows whether the revert restored pre_hash
		if ev.PostHash == p.PreHash {
			err = errors.Join(err, drv.Forget(ctx, conn, c.ID))
		}
		return d.failed(ev, out, err)
	}
	if c.PostHash, err = runningHash(ctx, conn, g); err != nil {
		return d.failed(ev, out, errors.Join(err, drv.Rollback(ctx, conn, c.ID)))
	}
	ev.PostHash, ev.Outcome = c.PostHash, "ok"
	if d.record(ev) != nil {
		drv.Rollback(ctx, conn, c.ID)
		return ChangeOutput{}, errors.New("the audit log cannot be written, so the change was reverted")
	}
	d.Changes.Commit(c)
	committed = true
	time.AfterFunc(c.Deadline.Sub(d.Changes.Now())+grace(drv), d.sweep)

	f, _ := output.NewFilter(nil, nil, "")
	out.Diff, out.Redactions, out.Truncation = f.Text(diff, false)
	out.Outcome, out.PostHash, out.Deadline, out.Untrusted = "applied", c.PostHash, ev.Deadline, []string{"diff"}
	out.Warning = drv.Warning(c.ID)
	return out, nil
}

// pending locks the session's change for confirm or rollback; unlock when done.
func (d Deps) pending(id, sid string) (*change.Change, error) {
	c, err := d.Changes.Get(id, sid)
	if err != nil {
		return nil, err
	}
	c.Lock()
	if c.Done {
		c.Unlock()
		return nil, change.ErrUnknownChange
	}
	return c, nil
}

// onDevice runs step on a fresh session, then on the apply session if the
// fresh one fails: IOS-XE may tie confirm and revert to the session that
// started the timer (unverified, research #5).
func onDevice(ctx context.Context, fresh timed, c *change.Change, step func(change.Conn) error) (string, error) {
	err := step(fresh)
	if err == nil {
		return "new_session", nil
	}
	if err2 := step(c.Conn); err2 != nil {
		return "", errors.Join(err, err2)
	}
	return "apply_session", nil
}

// confirm proves the device is still reachable on a fresh session and
// still holds the applied config, then stops the revert.
func (d Deps) confirm(ctx context.Context, sid, client string, in ChangeInput) (ChangeOutput, error) {
	ev := audit.Event{Event: "confirm", MCPSession: sid, Client: client, Reason: cleanReason(in.Reason), ChangeID: in.ChangeID}
	if err := checkReason(in.Reason); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	c, err := d.pending(in.ChangeID, sid)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	defer c.Unlock()
	ev = writeEvent("confirm", sid, client, in.Reason, c.Plan, c)
	if !d.Changes.Now().Before(c.Deadline) {
		return ChangeOutput{}, d.refuse(ev, "refused", errors.New("the deadline has passed; the change reverts"))
	}
	g, err := d.target(ctx, c.Plan)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	conn, err := d.dial(ctx, g, c.Plan.Username)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("not confirmed, the change reverts at its deadline: %w", err))
	}
	defer conn.Close()
	switch h, err := runningHash(ctx, conn, g); {
	case err != nil:
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	case h != c.PostHash:
		return ChangeOutput{}, d.refuse(ev, "refused", errors.New("the running config changed since apply; not confirmed, the change reverts at its deadline"))
	}
	if err := d.begin(ev); err != nil {
		return ChangeOutput{}, err
	}
	out := ChangeOutput{Device: c.Plan.Device, ChangeID: c.ID, PostHash: c.PostHash}
	drv := changeDriver(c.Plan.Driver, c.Plan.Revert)
	via, err := onDevice(ctx, conn, c, func(s change.Conn) error { return drv.Confirm(ctx, s, c.ID) })
	ev.Detail = map[string]string{"via": via}
	if err != nil {
		return d.failed(ev, out, err)
	}
	// the device has confirmed, so the change is no longer pending either way; an
	// unverified result is not recorded as confirmed, which keeps save refused
	if h, herr := runningHash(ctx, conn, g); herr != nil || h != c.PostHash {
		d.Changes.End(c, false)
		ev.Outcome = "confirmed_unverified"
		ev.Error = cmp.Or(herr, errors.New("the running config no longer matches post_hash after confirm")).Error()
		d.audit(ev)
		out.Outcome = "confirmed_unverified"
		return out, nil
	}
	d.Changes.End(c, true)
	ev.Outcome = "ok"
	d.audit(ev)
	out.Outcome = "confirmed"
	return out, nil
}

// rollback reverts now and checks the device is back at pre_hash.
func (d Deps) rollback(ctx context.Context, sid, client string, in ChangeInput) (ChangeOutput, error) {
	ev := audit.Event{Event: "rollback", MCPSession: sid, Client: client, Reason: cleanReason(in.Reason), ChangeID: in.ChangeID}
	if err := checkReason(in.Reason); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	c, err := d.pending(in.ChangeID, sid)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	defer c.Unlock()
	ev = writeEvent("rollback", sid, client, in.Reason, c.Plan, c)
	g, err := d.target(ctx, c.Plan)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	conn, err := d.dial(ctx, g, c.Plan.Username)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("the change reverts at its deadline: %w", err))
	}
	defer conn.Close()
	if err := d.begin(ev); err != nil {
		return ChangeOutput{}, err
	}
	out := ChangeOutput{Device: c.Plan.Device, ChangeID: c.ID, PreHash: c.Plan.PreHash}
	drv := changeDriver(c.Plan.Driver, c.Plan.Revert)
	via, err := onDevice(ctx, conn, c, func(s change.Conn) error { return drv.Rollback(ctx, s, c.ID) })
	ev.Detail = map[string]string{"via": via}
	if err != nil {
		return d.failed(ev, out, err)
	}
	d.Changes.End(c, false)
	h, err := runningHash(ctx, conn, g)
	if err == nil && h != c.Plan.PreHash {
		err = errors.New("reverted, but the running config does not match pre_hash")
	}
	if err == nil { // only a verified revert drops the marker
		err = drv.Forget(ctx, conn, c.ID)
	}
	if err != nil {
		return d.failed(ev, out, err)
	}
	ev.Outcome = "ok"
	d.audit(ev)
	out.Outcome = "rolled_back"
	return out, nil
}

// sweep is the one-shot check of every change past its deadline (plus
// grace): the device timer should have reverted it, or the server reverts it now.
func (d Deps) sweep() {
	for _, c := range d.Changes.Changes() {
		if d.Changes.Now().Before(c.Deadline.Add(grace(changeDriver(c.Plan.Driver, c.Plan.Revert)))) {
			continue
		}
		c.Lock()
		if !c.Done {
			d.Changes.End(c, false)
			d.deadlineCheck(c)
		}
		c.Unlock()
	}
}

func (d Deps) deadlineCheck(c *change.Change) {
	// shortcut: one request timeout covers dial, rollback and re-hash; a slow
	// NX-OS rollback audits unreachable and keeps its checkpoint. Measure on hardware.
	ctx, cancel := context.WithTimeout(context.Background(), d.Config.RequestTimeout)
	defer cancel()
	ev := writeEvent("deadline", c.Plan.Session, "", c.Plan.Reason, c.Plan, c)
	drv := changeDriver(c.Plan.Driver, c.Plan.Revert)
	var derr error // the server's revert or dropping the marker
	h, err := func() (string, error) {
		g, err := d.target(ctx, c.Plan)
		if err != nil {
			return "", err
		}
		conn, err := d.dial(ctx, g, c.Plan.Username)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		if !drv.DeviceReverts() {
			derr = drv.Rollback(ctx, conn, c.ID)
		}
		h, err := runningHash(ctx, conn, g)
		if err == nil && h == c.Plan.PreHash {
			derr = errors.Join(derr, drv.Forget(ctx, conn, c.ID))
		}
		return h, err
	}()
	switch {
	case err != nil:
		ev.Outcome, ev.Error = "unreachable", output.Cap(output.Sanitize(err.Error()), output.LongCap)
	case h == c.Plan.PreHash:
		ev.Outcome = "reverted"
	default:
		ev.Outcome = "not_reverted"
	}
	if derr != nil && ev.Error == "" {
		ev.Error = output.Cap(output.Sanitize(derr.Error()), output.LongCap)
	}
	ev.Detail = map[string]string{"running_hash": h}
	d.audit(ev)
}

// save copies running to startup, only at the post-hash of the last change
// this server confirmed on the device and with nothing pending.
func (d Deps) save(ctx context.Context, sid, client string, in ChangeInput) (ChangeOutput, error) {
	ev := audit.Event{Event: "save", MCPSession: sid, Client: client, Reason: cleanReason(in.Reason), Device: in.Device}
	switch {
	case !d.Config.AllowSave:
		return ChangeOutput{}, d.refuse(ev, "refused", errors.New("save needs --allow-save"))
	case checkReason(in.Reason) != nil:
		return ChangeOutput{}, d.refuse(ev, "refused", checkReason(in.Reason))
	}
	g, err := d.gate(ctx, in.Device)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	ev.Device, ev.Address, ev.Platform, ev.CredRef = g.dev.Name, g.addr.String(), g.plat.Driver, g.dev.WriteRef
	ev.HostKey, _ = sshcli.HostKey(d.Config.KnownHosts, g.addr, g.dev.Port)
	drv := changeDriver(g.plat.Driver, g.plat.Revert)
	ok := drv != nil
	want := d.Changes.Confirmed(g.dev.Name)
	switch {
	case !ok || g.dev.Adhoc || g.dev.WriteRef == "":
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("%s cannot be saved by this server", g.dev.Name))
	case want == "":
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("no change confirmed by this server is on record for %s (records do not survive a restart)", g.dev.Name))
	}
	// holds the device against an apply; a save counts toward no limit
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
	if p, err := drv.Pending(ctx, conn); err != nil || p {
		return ChangeOutput{}, d.refuse(ev, "refused", cmp.Or(err, errors.New("a change is pending on the device")))
	}
	switch h, err := runningHash(ctx, conn, g); {
	case err != nil:
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	case h != want:
		return ChangeOutput{}, d.refuse(ev, "refused", errors.New("the running config differs from the last change this server confirmed"))
	}
	ev.PostHash = want
	if err := d.begin(ev); err != nil {
		return ChangeOutput{}, err
	}
	out := ChangeOutput{Device: g.dev.Name, PostHash: want}
	if err := drv.Save(ctx, conn); err != nil {
		return d.failed(ev, out, err)
	}
	ev.Outcome = "ok"
	d.audit(ev)
	out.Outcome = "saved"
	return out, nil
}
