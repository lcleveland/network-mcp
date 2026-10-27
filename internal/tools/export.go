package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/audit"
	"github.com/lcleveland/network-mcp/internal/export"
	"github.com/lcleveland/network-mcp/internal/output"
)

// MaxExport caps the devices in one network_export call.
const MaxExport = 50

type ExportInput struct {
	Devices     []string `json:"devices" jsonschema:"device names from the inventory, at most 50, fetched one after another"`
	Kinds       []string `json:"kinds" jsonschema:"which configs to export: running, startup or both"`
	Destination string   `json:"destination" jsonschema:"a configured destination name"`
	Reason      string   `json:"reason" jsonschema:"why this export is made; recorded in the audit log"`
}

type ExportResult struct {
	Device      string `json:"device"`
	Kind        string `json:"kind"`
	Destination string `json:"destination,omitempty"`
	Ref         string `json:"ref,omitempty"`
	Changed     bool   `json:"changed"`
	SHA256      string `json:"sha256,omitempty"`
	Error       string `json:"error,omitempty"`
}

type ExportOutput struct {
	Results   []ExportResult `json:"results"`
	Untrusted []string       `json:"_untrusted"`
}

// exportAudit is the audit detail of one export. Never the body.
type exportAudit struct {
	Destination string            `json:"destination"`
	Devices     []string          `json:"devices"`
	Kinds       []string          `json:"kinds"`
	SHA256      map[string]string `json:"sha256,omitempty"` // <device>/<kind> to hash
	Refs        []string          `json:"refs,omitempty"`
	Redact      bool              `json:"redact"`
	Reason      string            `json:"reason"`
	Session     string            `json:"session,omitempty"`
}

func registerExport(s *mcp.Server, d Deps) {
	sinks := map[string]export.Sink{}
	for n, dst := range d.Config.File.Destinations {
		sk, err := export.New(n, dst, d.Config.CredentialsDir)
		if err != nil {
			panic(err) // config.ParseFile validated every destination
		}
		sinks[n] = sk
	}
	in, err := jsonschema.For[ExportInput](nil)
	if err != nil {
		panic(err)
	}
	in.Properties["devices"].MinItems, in.Properties["devices"].MaxItems = new(1), new(MaxExport)
	in.Properties["kinds"].MinItems = new(1)
	in.Properties["kinds"].Items.Enum = []any{"running", "startup"}
	for _, n := range slices.Sorted(maps.Keys(sinks)) {
		in.Properties["destination"].Enum = append(in.Properties["destination"].Enum, n)
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_export",
		Title: "Export device configs to a destination",
		Description: "Fetch the running and/or startup config of up to 50 devices and write them to a configured destination " +
			"as <device>/<kind>.txt, in one batch. Secrets are replaced with <redacted> before anything is written, unless " +
			"the destination's operator turned that off. A device is written whole or not at all; an unchanged config is not " +
			"rewritten (changed: false). The result gives per device and kind the ref (a path, commit or object key), changed and sha256, or an error; " +
			"never config text. Every export is audit-logged with its reason.\n\n" + UntrustedNote,
		InputSchema: in,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: new(false), IdempotentHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ExportInput) (*mcp.CallToolResult, ExportOutput, error) {
		sink := sinks[in.Destination]
		switch {
		case strings.TrimSpace(in.Reason) == "":
			return nil, ExportOutput{}, errors.New("reason is required")
		case len(in.Devices) == 0 || len(in.Devices) > MaxExport:
			return nil, ExportOutput{}, fmt.Errorf("give 1 to %d devices, not %d", MaxExport, len(in.Devices))
		case len(in.Kinds) == 0:
			return nil, ExportOutput{}, errors.New("kinds is required")
		case sink == nil:
			return nil, ExportOutput{}, fmt.Errorf("unknown destination %q", in.Destination)
		}
		for _, k := range in.Kinds {
			if k != "running" && k != "startup" {
				return nil, ExportOutput{}, fmt.Errorf("kind must be running or startup, not %q", k)
			}
		}
		for _, dev := range in.Devices {
			if err := export.ValidName(dev); err != nil {
				return nil, ExportOutput{}, err
			}
		}
		dst := d.Config.File.Destinations[in.Destination]
		det := exportAudit{Destination: in.Destination, Devices: in.Devices, Kinds: in.Kinds, SHA256: map[string]string{},
			Redact: dst.Redact == nil || *dst.Redact, Reason: in.Reason, Session: req.Session.ID()}
		if !det.Redact {
			d.Log.Warn("exporting configs unredacted", "destination", in.Destination, "devices", in.Devices)
		}

		out := ExportOutput{Untrusted: []string{"results.error"}}
		var arts []export.Artifact
		var at []int // index in out.Results of each artifact
		for _, dev := range in.Devices {
			var got []export.Artifact
			var ferr error
			for _, k := range in.Kinds {
				raw, err := d.FetchConfig(ctx, dev, k, "")
				if ferr = err; err != nil {
					break
				}
				if det.Redact {
					raw, _ = output.Redact(output.Sanitize(raw))
				}
				got = append(got, export.NewArtifact(dev, k, []byte(raw), det.Redact))
			}
			for i, k := range in.Kinds {
				r := ExportResult{Device: dev, Kind: k}
				if ferr != nil {
					r.Error, _, _ = deviceError(ferr) // nothing of this device is written
				} else {
					r.SHA256 = got[i].SHA256
					det.SHA256[dev+"/"+k] = r.SHA256
					at = append(at, len(out.Results))
					arts = append(arts, got[i])
				}
				out.Results = append(out.Results, r)
			}
		}

		// fail closed: no audit line, no write
		if err := d.Audit.Write(audit.Event{Event: "export", Outcome: "allowed", Detail: det}); err != nil {
			return nil, ExportOutput{}, fmt.Errorf("export refused: audit log unavailable: %w", err)
		}
		var rs []export.Receipt
		var perr error
		if len(arts) > 0 {
			msg := in.Reason
			if det.Session != "" {
				msg += "\n\nMCP-Session: " + det.Session
			}
			rs, perr = sink.Put(ctx, arts, msg)
		}
		if perr == nil && len(rs) != len(arts) {
			perr = fmt.Errorf("sink returned %d receipts for %d configs", len(rs), len(arts))
		}
		for i, j := range at {
			r := &out.Results[j]
			if i < len(rs) {
				r.Destination, r.Ref, r.Changed = rs[i].Destination, rs[i].Ref, rs[i].Changed
				det.Refs = append(det.Refs, rs[i].Ref)
				if perr != nil && len(rs) == len(arts) { // all stored, then a later step failed (a push)
					r.Error = perr.Error()
				}
			} else {
				r.Error = "not written: " + perr.Error()
			}
		}
		e := audit.Event{Event: "export", Outcome: "ok", Detail: det}
		if perr != nil {
			e.Outcome, e.Error = "error", perr.Error()
		}
		if err := d.Audit.Write(e); err != nil {
			d.Log.Error("audit write failed", "err", err)
		}
		return nil, out, nil
	})
}
