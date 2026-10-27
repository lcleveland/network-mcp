package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/audit"
	"github.com/lcleveland/network-mcp/internal/change"
	"github.com/lcleveland/network-mcp/internal/change/deny"
	"github.com/lcleveland/network-mcp/internal/change/hash"
	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshcli"
)

const maxReason = 512

type ChangeInput struct {
	Action string   `json:"action" jsonschema:"plan: check and record lines for one device; status: this session's pending plans"`
	Device string   `json:"device,omitempty" jsonschema:"plan: device name from the inventory"`
	Lines  []string `json:"lines,omitempty" jsonschema:"plan: config lines as typed after configure terminal, at most 200"`
	Reason string   `json:"reason,omitempty" jsonschema:"plan: why the change is made; required and audited"`
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
	MaxPendingChanges int `json:"max_pending_changes"`
}

type ChangeOutput struct {
	PlanID     string        `json:"plan_id,omitempty"`
	Device     string        `json:"device,omitempty"`
	Diff       string        `json:"diff,omitempty"` // the planned lines as + additions
	PreHash    string        `json:"pre_hash,omitempty"`
	Expires    string        `json:"expires,omitempty"`
	Plans      []PlanView    `json:"plans,omitempty"`
	Changes    *ChangeStatus `json:"changes,omitempty"`
	Redactions int           `json:"_redactions"`
}

func (d Deps) audit(e audit.Event) {
	if err := d.Audit.Write(e); err != nil {
		d.Log.Error("audit write failed", "err", err)
	}
}

func (d Deps) changeCount() *ChangeStatus {
	return &ChangeStatus{len(d.Changes.Plans()), d.Config.MaxPendingChanges}
}

func registerChange(s *mcp.Server, d Deps) {
	in, err := jsonschema.For[ChangeInput](nil)
	if err != nil {
		panic(err)
	}
	in.Properties["action"].Enum = []any{"plan", "status"}
	in.Properties["lines"].MaxItems = new(deny.MaxLines)
	d.Changes.Expired = func(p change.Plan) {
		d.audit(audit.Event{Event: "plan", Outcome: "expired", MCPSession: p.Session, Reason: p.Reason, Device: p.Device,
			Address: p.Address, Platform: p.Driver, HostKey: p.HostKey, CredRef: p.WriteRef, Username: p.Username,
			PlanID: p.ID, PreHash: p.PreHash})
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_change",
		Title: "Plan a config change on one device",
		Description: "Plan a configuration change on one IOS-XE or NX-OS device (action plan): device, lines (at most 200, " +
			"as typed after configure terminal) and reason. The server reads and hashes the running config with the " +
			"device's write credential and refuses the whole plan if any line touches the management plane (AAA, users, " +
			"lines, SSH, crypto, SNMP, logging, boot, the management VRF, interface and ACLs, and more; abbreviations " +
			"count) or is end, exit, do or configure. A plan returns plan_id, the lines as a diff, pre_hash and its " +
			"expiry (10 minutes); it is bound to this session, used once, and never changes the device.\n\n" +
			"action status lists this session's pending plans.\n\n" + UntrustedNote,
		InputSchema: in,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ChangeInput) (*mcp.CallToolResult, ChangeOutput, error) {
		sid, client := session(req)
		switch {
		case !d.Config.AllowConfig: // unreachable unless registered by mistake
			return nil, ChangeOutput{}, errors.New("network_change needs --allow-config")
		case in.Action == "status":
			return nil, d.changeStatus(sid), nil
		case in.Action != "plan":
			return nil, ChangeOutput{}, fmt.Errorf("unknown action %q (want plan or status)", in.Action)
		}
		out, err := d.plan(ctx, sid, client, in)
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
	return out
}

// plan never changes the device: it reads the running config only.
func (d Deps) plan(ctx context.Context, sid, client string, in ChangeInput) (ChangeOutput, error) {
	var out ChangeOutput
	redacted := make([]string, len(in.Lines))
	for i, l := range in.Lines {
		var n int
		redacted[i], n = output.Redact(output.Sanitize(l))
		out.Redactions += n
	}
	ev := audit.Event{Event: "plan", MCPSession: sid, Client: client, Reason: output.Cap(output.Sanitize(in.Reason), maxReason),
		Device: in.Device, Commands: redacted}
	refuse := func(outcome string, err error) (ChangeOutput, error) {
		msg, _ := output.Field(err.Error(), output.LongCap)
		ev.Outcome, ev.Error = outcome, msg
		d.audit(ev)
		return ChangeOutput{}, errors.New(msg)
	}

	if strings.TrimSpace(in.Reason) == "" || len(in.Reason) > maxReason {
		return refuse("refused", fmt.Errorf("reason is required, at most %d bytes", maxReason))
	}
	list, err := deny.New(d.Config.File.WriteDeny)
	if err != nil {
		return refuse("refused", err)
	}
	if _, err := list.Check(in.Lines, deny.Derived{}); err != nil { // before touching the device
		return refuse("denied", err)
	}
	g, err := d.gate(ctx, in.Device)
	if err != nil {
		return refuse("refused", err)
	}
	ev.Device, ev.Address, ev.Platform, ev.CredRef = g.dev.Name, g.addr.String(), g.plat.Driver, g.dev.WriteRef
	switch {
	case g.dev.Adhoc:
		return refuse("refused", errors.New("ad-hoc devices cannot be changed"))
	case g.plat.Driver != platform.IOSXE && g.plat.Driver != platform.NXOS:
		return refuse("refused", fmt.Errorf("%s uses the %s driver; only %s and %s devices can be changed", g.dev.Name, g.plat.Driver, platform.IOSXE, platform.NXOS))
	case g.dev.WriteRef == "":
		return refuse("refused", fmt.Errorf("no rule gives %s a write_ref, so it cannot be changed (the read_ref is never used)", g.dev.Name))
	}
	c, err := creds.Read(d.Config.CredentialsDir, g.dev.WriteRef)
	if err != nil {
		return refuse("refused", err)
	}
	ev.Username = c.Username
	if ev.HostKey, err = sshcli.HostKey(d.Config.KnownHosts, g.addr, g.dev.Port); err != nil {
		return refuse("refused", err)
	}
	g.ref = g.dev.WriteRef
	raw, err := d.fetch(ctx, g, g.plat.Config.Running)
	if err != nil {
		return refuse("refused", fmt.Errorf("reading the running config: %w", err))
	}
	lines, err := list.Check(in.Lines, deny.Derive(raw, g.addr))
	if err != nil {
		return refuse("denied", err)
	}
	ev.PreHash = hash.Sum(raw)

	p, err := d.Changes.Add(change.Plan{
		Device: g.dev.Name, Address: ev.Address, HostKey: ev.HostKey, Driver: g.plat.Driver, Lines: lines,
		PreHash: ev.PreHash, WriteRef: g.dev.WriteRef, Username: c.Username, Reason: in.Reason, Session: sid,
	}, func(p change.Plan) error {
		ev.PlanID, ev.Outcome = p.ID, "ok"
		return d.Audit.Write(ev)
	})
	switch {
	case err != nil && ev.PlanID == "":
		return refuse("refused", err)
	case err != nil:
		d.Log.Error("audit write failed; plan refused", "err", err)
		return ChangeOutput{}, errors.New("the audit log cannot be written, so the plan is refused")
	}
	diff := make([]string, len(lines))
	for i, l := range lines {
		diff[i], _ = output.Redact(output.Sanitize(l))
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
