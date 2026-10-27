package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/audit"
	"github.com/lcleveland/network-mcp/internal/change"
	"github.com/lcleveland/network-mcp/internal/change/deny"
	"github.com/lcleveland/network-mcp/internal/change/hash"
	"github.com/lcleveland/network-mcp/internal/change/iosxe"
	"github.com/lcleveland/network-mcp/internal/change/nxos"
	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshcli"
)

const maxReason = 512

func checkReason(r string) error {
	if strings.TrimSpace(r) == "" || len(r) > maxReason {
		return fmt.Errorf("reason is required, at most %d bytes", maxReason)
	}
	return nil
}

// cleanReason is a reason as audited.
func cleanReason(r string) string { return output.Cap(output.Sanitize(r), maxReason) }

type ChangeInput struct {
	Action        string   `json:"action" jsonschema:"plan, apply, confirm, rollback, save or status"`
	Device        string   `json:"device,omitempty" jsonschema:"plan, save: device name from the inventory"`
	Lines         []string `json:"lines,omitempty" jsonschema:"plan: config lines as typed after configure terminal, at most 200"`
	Reason        string   `json:"reason,omitempty" jsonschema:"every action but status: why; required and audited"`
	PlanID        string   `json:"plan_id,omitempty" jsonschema:"apply: the plan_id from plan"`
	RevertMinutes int      `json:"revert_minutes,omitempty" jsonschema:"apply: minutes until the device reverts an unconfirmed change, 2 to 15 (default 5)"`
	ChangeID      string   `json:"change_id,omitempty" jsonschema:"confirm, rollback, status: the change_id from apply"`
}

// ChangeView is a pending change in status.
type ChangeView struct {
	ChangeID string `json:"change_id"`
	Device   string `json:"device"`
	PostHash string `json:"post_hash"`
	Deadline string `json:"deadline"`
}

type PlanView struct {
	PlanID  string `json:"plan_id"`
	Device  string `json:"device"`
	PreHash string `json:"pre_hash"`
	Expires string `json:"expires"`
}

// ChangeStatus is also shown by network_status.
type ChangeStatus struct {
	PendingPlans      int `json:"pending_plans"` // every session's
	PendingChanges    int `json:"pending_changes"`
	MaxPendingChanges int `json:"max_pending_changes"`
}

type ChangeOutput struct {
	PlanID      string             `json:"plan_id,omitempty"`
	ChangeID    string             `json:"change_id,omitempty"`
	Device      string             `json:"device,omitempty"`
	Outcome     string             `json:"outcome,omitempty"`
	Diff        string             `json:"diff,omitempty"` // plan: the lines as + additions; apply: the device's diff
	PreHash     string             `json:"pre_hash,omitempty"`
	PostHash    string             `json:"post_hash,omitempty"`
	Expires     string             `json:"expires,omitempty"`
	Deadline    string             `json:"deadline,omitempty"`
	Plans       []PlanView         `json:"plans,omitempty"`
	Pending     []ChangeView       `json:"pending,omitempty"`
	Changes     *ChangeStatus      `json:"changes,omitempty"`
	Warning     string             `json:"warning,omitempty"`           // NX-OS apply: the revert is server-driven
	Stale       []string           `json:"stale_checkpoints,omitempty"` // status with an NX-OS change_id
	DeviceError string             `json:"device_error,omitempty"`
	Untrusted   []string           `json:"_untrusted,omitempty"`
	Redactions  int                `json:"_redactions"`
	Truncation  *output.Truncation `json:"_truncation,omitempty"`
}

// audit writes e best-effort: a failure is only logged.
func (d Deps) audit(e audit.Event) { d.record(e) }

// record writes e and logs a failure; a caller that must not go on without
// the line checks the error.
func (d Deps) record(e audit.Event) error {
	err := d.Audit.Write(e)
	if err != nil {
		d.Log.Error("audit write failed", "err", err)
	}
	return err
}

// refuse audits a refusal and returns it, capped and redacted.
func (d Deps) refuse(ev audit.Event, outcome string, err error) error {
	msg, _ := output.Field(err.Error(), output.LongCap)
	ev.Outcome, ev.Error = outcome, msg
	d.audit(ev)
	return errors.New(msg)
}

// begin writes the line that must exist before a write reaches the device.
func (d Deps) begin(ev audit.Event) error {
	ev.Outcome = "started"
	if d.record(ev) != nil {
		return errors.New("the audit log cannot be written, so the action is refused")
	}
	return nil
}

func redactLines(lines []string) ([]string, int) {
	out, total := make([]string, len(lines)), 0
	for i, l := range lines {
		var n int
		out[i], n = output.Redact(output.Sanitize(l))
		total += n
	}
	return out, total
}

// timed gives every command on a session its own request timeout, so a
// session kept open for confirm outlives the apply call.
type timed struct {
	*sshcli.Session
	d time.Duration
}

func (t timed) Run(ctx context.Context, cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, t.d)
	defer cancel()
	return t.Session.Run(ctx, cmd)
}

func (t timed) Ask(ctx context.Context, cmd string, q *regexp.Regexp) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, t.d)
	defer cancel()
	return t.Session.Ask(ctx, cmd, q)
}

// target re-gates a plan's device and checks that its address and pinned
// host key are still the ones the plan bound. Writes use the plan's ref.
func (d Deps) target(ctx context.Context, p change.Plan) (*gated, error) {
	g, err := d.gate(ctx, p.Device)
	if err != nil {
		return nil, err
	}
	hk, err := sshcli.HostKey(d.Config.KnownHosts, g.addr, g.dev.Port)
	switch {
	case err != nil:
		return nil, err
	case g.addr.String() != p.Address || hk != p.HostKey:
		return nil, fmt.Errorf("the address or pinned host key of %s changed since the plan; plan again", p.Device)
	}
	g.ref = p.WriteRef
	return g, nil
}

// dial opens a fresh session with g's write ref (as user, when set). The
// prompt must be privileged: the server never runs enable.
func (d Deps) dial(ctx context.Context, g *gated, user string) (timed, error) {
	c, err := creds.Read(d.Config.CredentialsDir, g.ref)
	if err != nil {
		return timed{}, err
	}
	if user != "" && c.Username != user {
		return timed{}, fmt.Errorf("the write_ref %s no longer holds the planned username", g.ref)
	}
	s, err := d.openAs(ctx, g, c)
	if err != nil {
		return timed{}, err
	}
	if !strings.HasSuffix(s.Prompt(), "#") {
		s.Close()
		return timed{}, errors.New("the write account's prompt is not privileged (#); the server never runs enable")
	}
	return timed{s, d.Config.RequestTimeout}, nil
}

func (d Deps) changeCount() *ChangeStatus {
	return &ChangeStatus{len(d.Changes.Plans()), len(d.Changes.Changes()), d.Config.MaxPendingChanges}
}

func registerChange(s *mcp.Server, d Deps) {
	in, err := jsonschema.For[ChangeInput](nil)
	if err != nil {
		panic(err)
	}
	in.Properties["action"].Enum = []any{"plan", "apply", "confirm", "rollback", "status"}
	if d.Config.AllowSave {
		in.Properties["action"].Enum = append(in.Properties["action"].Enum, "save")
	}
	in.Properties["lines"].MaxItems = new(deny.MaxLines)
	in.Properties["revert_minutes"].Minimum, in.Properties["revert_minutes"].Maximum = new(float64(MinRevert)), new(float64(MaxRevert))
	d.Changes.Expired = func(p change.Plan) {
		d.audit(audit.Event{Event: "plan", Outcome: "expired", MCPSession: p.Session, Reason: p.Reason, Device: p.Device,
			Address: p.Address, Platform: p.Driver, HostKey: p.HostKey, CredRef: p.WriteRef, Username: p.Username,
			PlanID: p.ID, PreHash: p.PreHash})
	}
	save := ""
	if d.Config.AllowSave {
		save = "save (device, reason) runs copy running-config startup-config, only when nothing is pending on the device " +
			"and its running config still matches the last change this server confirmed there.\n\n"
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_change",
		Title: "Change the config of one device",
		Description: "Change the configuration of one device in steps; every step but status needs a reason, which is audited.\n\n" +
			"plan: device, lines (at most 200, as typed after configure terminal). The server reads and hashes the running " +
			"config with the device's write credential and refuses the whole plan if any line touches the management plane " +
			"(AAA, users, lines, SSH, crypto, SNMP, logging, boot, the management VRF, interface and ACLs, and more; " +
			"abbreviations count) or is end, exit, do or configure. It returns plan_id, the lines as a diff, pre_hash and its " +
			"expiry (10 minutes); a plan is bound to this session, used once, and never changes the device.\n\n" +
			"apply: plan_id, revert_minutes (2-15, default 5). The device must still have the planned pre_hash. IOS-XE: the " +
			"device must have archive path set, no revert timer pending and no configuration lock. The lines go in under " +
			"configure terminal revert timer, so the device reverts on its own unless confirmed before the deadline; any % " +
			"error reverts at once. NX-OS: refused while any network-mcp-* checkpoint is on the device. The server creates " +
			"checkpoint network-mcp-<change_id>, sends the lines, and rolls back to it at the deadline unless confirmed; any " +
			"error rolls back at once. " + fmt.Sprintf(nxos.Warning, "<change_id>") + " IOS-XE on a platform with revert: " +
			"server (no archive needed) works the same way with a flash:network-mcp-<change_id>.cfg snapshot restored by " +
			"configure replace, and the same risk. Returns change_id, deadline, post_hash, the device's diff and, when the " +
			"server reverts, that warning.\n\n" +
			"confirm: change_id. From a new SSH session (proving the device is still reachable), checks post_hash and stops " +
			"the revert (server-reverted: deletes the checkpoint or snapshot). It does not save.\n\nrollback: change_id. " +
			"Reverts now and checks pre_hash (server-reverted: then deletes the checkpoint or snapshot).\n\n" + save +
			"status: this session's plans and pending changes; with change_id of a server-reverted change, also the other " +
			"network-mcp-* checkpoints or snapshots on its device (stale_checkpoints). After a restart there are no change " +
			"records; list leftovers with network_status and device.\n\n" + UntrustedNote,
		InputSchema: in,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ChangeInput) (*mcp.CallToolResult, ChangeOutput, error) {
		sid, client := session(req)
		if !d.Config.AllowConfig { // unreachable unless registered by mistake
			return nil, ChangeOutput{}, errors.New("network_change needs --allow-config")
		}
		act := map[string]func(context.Context, string, string, ChangeInput) (ChangeOutput, error){
			"plan": d.plan, "apply": d.apply, "confirm": d.confirm, "rollback": d.rollback, "save": d.save,
		}[in.Action]
		switch {
		case in.Action == "status" && in.ChangeID != "":
			out := d.changeStatus(sid)
			var err error
			if out.Stale, err = d.stale(ctx, sid, in.ChangeID); len(out.Stale) > 0 {
				out.Untrusted = []string{"stale_checkpoints"}
			}
			return nil, out, err
		case in.Action == "status":
			return nil, d.changeStatus(sid), nil
		case act == nil:
			return nil, ChangeOutput{}, fmt.Errorf("unknown action %q", in.Action)
		}
		out, err := act(ctx, sid, client, in)
		return nil, out, err
	})
}

func (d Deps) changeStatus(sid string) ChangeOutput {
	out := ChangeOutput{Changes: d.changeCount()}
	for _, p := range d.Changes.Plans() {
		if p.Session == sid {
			out.Plans = append(out.Plans, PlanView{PlanID: p.ID, Device: p.Device, PreHash: p.PreHash, Expires: p.Expires.UTC().Format(time.RFC3339)})
		}
	}
	for _, c := range d.Changes.Changes() {
		if c.Plan.Session == sid {
			out.Pending = append(out.Pending, ChangeView{c.ID, c.Plan.Device, c.PostHash, c.Deadline.UTC().Format(time.RFC3339)})
		}
	}
	return out
}

// stale lists the network-mcp-* checkpoints (NX-OS) or flash snapshots
// (server-reverted IOS-XE), other than the change's own, on the device of
// the session's change: changes nobody confirmed or rolled back. It sends no
// config and is not audited.
func (d Deps) stale(ctx context.Context, sid, id string) ([]string, error) {
	c, err := d.Changes.Get(id, sid)
	if err != nil || changeDriver(c.Plan.Driver, c.Plan.Revert).DeviceReverts() {
		return nil, err
	}
	list, own := nxos.Checkpoints, nxos.Prefix+c.ID
	if c.Plan.Driver == platform.IOSXE {
		list, own = iosxe.Snapshots, iosxe.Prefix+c.ID+".cfg"
	}
	g, err := d.target(ctx, c.Plan)
	if err != nil {
		return nil, err
	}
	conn, err := d.dial(ctx, g, c.Plan.Username)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	names, err := list(ctx, conn)
	return slices.DeleteFunc(names, func(n string) bool { return n == own }), err
}

// plan never changes the device: it reads the running config only.
func (d Deps) plan(ctx context.Context, sid, client string, in ChangeInput) (ChangeOutput, error) {
	var out ChangeOutput
	redacted, n := redactLines(in.Lines)
	out.Redactions = n
	ev := audit.Event{Event: "plan", MCPSession: sid, Client: client, Reason: cleanReason(in.Reason),
		Device: in.Device, Commands: redacted}
	if err := checkReason(in.Reason); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	list, err := deny.New(d.Config.File.WriteDeny)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	if _, err := list.Check(in.Lines, deny.Derived{}); err != nil { // before touching the device
		return ChangeOutput{}, d.refuse(ev, "denied", err)
	}
	g, err := d.gate(ctx, in.Device)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	ev.Device, ev.Address, ev.Platform, ev.CredRef = g.dev.Name, g.addr.String(), g.plat.Driver, g.dev.WriteRef
	switch {
	case g.dev.Adhoc:
		return ChangeOutput{}, d.refuse(ev, "refused", errors.New("ad-hoc devices cannot be changed"))
	case drivers[g.plat.Driver] == nil:
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("%s uses the %s driver; only %s devices can be changed", g.dev.Name, g.plat.Driver, strings.Join(slices.Sorted(maps.Keys(drivers)), " and ")))
	case g.dev.WriteRef == "":
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("no rule gives %s a write_ref, so it cannot be changed (the read_ref is never used)", g.dev.Name))
	}
	c, err := creds.Read(d.Config.CredentialsDir, g.dev.WriteRef)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	ev.Username = c.Username
	if ev.HostKey, err = sshcli.HostKey(d.Config.KnownHosts, g.addr, g.dev.Port); err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	}
	g.ref = g.dev.WriteRef
	raw, err := d.fetch(ctx, g, g.plat.Config.Running)
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "refused", fmt.Errorf("reading the running config: %w", err))
	}
	lines, err := list.Check(in.Lines, deny.Derive(raw, g.addr))
	if err != nil {
		return ChangeOutput{}, d.refuse(ev, "denied", err)
	}
	ev.PreHash = hash.Sum(raw)

	p, err := d.Changes.Add(change.Plan{
		Device: g.dev.Name, Address: ev.Address, HostKey: ev.HostKey, Driver: g.plat.Driver, Revert: g.plat.Revert, Lines: lines,
		PreHash: ev.PreHash, WriteRef: g.dev.WriteRef, Username: c.Username, Reason: in.Reason, Session: sid,
	}, func(p change.Plan) error {
		ev.PlanID, ev.Outcome = p.ID, "ok"
		return d.record(ev)
	})
	switch {
	case err != nil && ev.PlanID == "":
		return ChangeOutput{}, d.refuse(ev, "refused", err)
	case err != nil:
		return ChangeOutput{}, errors.New("the audit log cannot be written, so the plan is refused")
	}
	diff, _ := redactLines(lines)
	for i := range diff {
		diff[i] = "+ " + diff[i]
	}
	out.PlanID, out.Device, out.Diff, out.PreHash = p.ID, p.Device, strings.Join(diff, "\n"), p.PreHash
	out.Expires = p.Expires.UTC().Format(time.RFC3339)
	return out, nil
}

func session(req *mcp.CallToolRequest) (id, client string) {
	if req == nil || req.Session == nil {
		return "", ""
	}
	if ip := req.Session.InitializeParams(); ip != nil && ip.ClientInfo != nil {
		client, _ = output.Field(ip.ClientInfo.Name, output.FieldCap)
	}
	return req.Session.ID(), client
}
