package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/inventory"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/sshcli"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// recordFields are the JSON keys of inventory.Device, for fields.
var recordFields = []string{"name", "address", "port", "platform", "tags", "driver", "profile",
	"read_ref", "write_ref", "snmp", "opted_in", "adhoc", "unreachable", "provenance"}

type InventoryInput struct {
	Action   string   `json:"action"`
	Name     string   `json:"name,omitempty" jsonschema:"list: a glob on the device name (*, ?, [..]), case-insensitive; get: the device name"`
	Platform string   `json:"platform,omitempty" jsonschema:"list: only this platform (as the source gives it)"`
	Driver   string   `json:"driver,omitempty" jsonschema:"list: only this driver (iosxe, nxos, generic_ssh)"`
	Tag      string   `json:"tag,omitempty" jsonschema:"list: only devices with this tag"`
	Fields   []string `json:"fields,omitempty" jsonschema:"list: return only these record fields (name is always returned)"`
	Limit    int      `json:"limit,omitempty" jsonschema:"list: at most this many rows; default 50, max 200"`
}

// Verdicts are the connect gates' answers, found without dialling the device.
type Verdicts struct {
	OptIn           bool   `json:"opt_in"`
	InPrefix        bool   `json:"in_prefix"`
	Prefix          string `json:"prefix,omitempty"` // the management prefix holding the address
	PrefixReason    string `json:"in_prefix_reason,omitempty"`
	HostKeyPinned   bool   `json:"host_key_pinned"` // a known_hosts entry exists; the key is not checked
	ReachableReason string `json:"reachable_reason,omitempty"`
}

type InventoryOutput struct {
	Rows       []map[string]any   `json:"rows,omitempty"`
	Total      *int               `json:"total,omitempty"`
	Device     *inventory.Device  `json:"device,omitempty"`
	Gate       *Verdicts          `json:"gate,omitempty"`
	Untrusted  []string           `json:"_untrusted"`
	Redactions int                `json:"_redactions"`
	Truncation *output.Truncation `json:"_truncation,omitempty"`
}

func registerInventory(s *mcp.Server, d Deps) {
	in, err := jsonschema.For[InventoryInput](nil)
	if err != nil {
		panic(err)
	}
	in.Properties["action"].Enum = []any{"list", "get"}
	in.Properties["fields"].Items.Enum = toAny(recordFields)
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_inventory",
		Title: "List and inspect inventory devices",
		Description: "The merged device inventory. It contacts no device.\n\n" +
			"list: devices filtered by name glob, platform, driver and tag, sorted by name, with total. " +
			"Over the limit, _truncation says how many matched.\n\n" +
			"get: one device's merged record, provenance (which source set each field), credential ref names " +
			"(never secrets) and the connect gate verdicts: opt_in, in_prefix (with the matched management prefix " +
			"or the reason), host_key_pinned (a known_hosts entry exists) and reachable_reason.\n\n" + UntrustedNote,
		InputSchema: in,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in InventoryInput) (*mcp.CallToolResult, InventoryOutput, error) {
		if in.Action == "get" {
			return d.inventoryGet(ctx, in.Name)
		}
		if in.Action != "list" {
			return nil, InventoryOutput{}, errors.New(`action must be "list" or "get"`)
		}
		return inventoryList(d.Inv.List(ctx), in)
	})
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// clean runs every source-supplied string through the output pipeline.
func (o *InventoryOutput) clean(s string) string {
	s, n := output.Field(s, output.FieldCap)
	o.Redactions += n
	return s
}

func (o *InventoryOutput) cleanDevice(d inventory.Device) inventory.Device {
	d.Name, d.Address, d.Platform, d.Unreachable = o.clean(d.Name), o.clean(d.Address), o.clean(d.Platform), o.clean(d.Unreachable)
	d.Tags = slices.Clone(d.Tags)
	for i := range d.Tags {
		d.Tags[i] = o.clean(d.Tags[i])
	}
	return d
}

func inventoryList(devs []*inventory.Device, in InventoryInput) (*mcp.CallToolResult, InventoryOutput, error) {
	for _, f := range in.Fields {
		if !slices.Contains(recordFields, f) {
			return nil, InventoryOutput{}, fmt.Errorf("unknown field %q; fields: %s", f, strings.Join(recordFields, ", "))
		}
	}
	if _, err := path.Match(in.Name, ""); err != nil {
		return nil, InventoryOutput{}, fmt.Errorf("bad name glob %q: %v", in.Name, err)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxLimit)
	out := InventoryOutput{Rows: []map[string]any{},
		Untrusted: []string{"rows[].name", "rows[].address", "rows[].platform", "rows[].tags", "rows[].unreachable"}}
	total := 0
	for _, dev := range devs {
		if ok, _ := path.Match(strings.ToLower(in.Name), strings.ToLower(dev.Name)); in.Name != "" && !ok ||
			in.Platform != "" && !strings.EqualFold(in.Platform, dev.Platform) ||
			in.Driver != "" && !strings.EqualFold(in.Driver, dev.Driver) ||
			in.Tag != "" && !slices.ContainsFunc(dev.Tags, func(t string) bool { return strings.EqualFold(t, in.Tag) }) {
			continue
		}
		if total++; len(out.Rows) == limit {
			continue
		}
		var row map[string]any
		b, _ := json.Marshal(out.cleanDevice(*dev))
		json.Unmarshal(b, &row)
		if len(in.Fields) > 0 {
			for k := range row {
				if k != "name" && !slices.Contains(in.Fields, k) {
					delete(row, k)
				}
			}
		}
		out.Rows = append(out.Rows, row)
	}
	out.Total = &total
	if len(out.Rows) < total {
		out.Truncation = &output.Truncation{Reason: "rows", Shown: len(out.Rows), Total: total, Hint: "narrow with name/platform/tag"}
	}
	// rows are capped fields, but many tags could still overflow the result
	for b, _ := json.Marshal(out); len(out.Rows) > 0 && len(b) > output.MaxResult-output.Envelope; b, _ = json.Marshal(out) {
		out.Rows = out.Rows[:len(out.Rows)*3/4]
		out.Truncation = &output.Truncation{Reason: "bytes", Shown: len(out.Rows), Total: total, Hint: "narrow with name/platform/tag or fields"}
	}
	return nil, out, nil
}

func (d Deps) inventoryGet(ctx context.Context, name string) (*mcp.CallToolResult, InventoryOutput, error) {
	if name == "" {
		return nil, InventoryOutput{}, errors.New("get needs name")
	}
	dev, err := d.Inv.Get(ctx, name)
	if err != nil {
		return nil, InventoryOutput{}, err
	}
	out := InventoryOutput{Untrusted: []string{"device.name", "device.address", "device.platform", "device.tags",
		"device.unreachable", "gate.in_prefix_reason", "gate.reachable_reason"}}
	v := &Verdicts{OptIn: dev.OptedIn, ReachableReason: out.clean(dev.Unreachable)}
	if dev.Address == "" {
		v.PrefixReason = "no address"
	} else if a, p, err := inventory.InPrefix(ctx, dev, d.Config.File.ManagementPrefixes, d.Lookup); err != nil {
		v.PrefixReason = out.clean(err.Error())
	} else {
		v.InPrefix, v.Prefix = true, p.String()
		v.HostKeyPinned = sshcli.Pinned(d.Config.KnownHosts, a, dev.Port)
	}
	c := out.cleanDevice(*dev)
	out.Device, out.Gate = &c, v
	return nil, out, nil
}
