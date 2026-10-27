package tools

import (
	"cmp"
	"context"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/mib"
	"github.com/lcleveland/network-mcp/internal/snmp"
)

type SNMPInput struct {
	Action  string   `json:"action" jsonschema:"get, walk (GETNEXT), bulkwalk (GETBULK) or resolve (name <-> OID, offline)"`
	Device  string   `json:"device,omitempty" jsonschema:"device name from the inventory; not used by resolve"`
	OIDs    []string `json:"oids,omitempty" jsonschema:"get and resolve: up to 16 OIDs, numeric or MIB names such as IF-MIB::ifDescr.1 or sysName.0"`
	OID     string   `json:"oid,omitempty" jsonschema:"walk and bulkwalk: the root of the subtree, numeric or a MIB name"`
	After   string   `json:"after,omitempty" jsonschema:"walk and bulkwalk: resume after this OID, as given by _truncation.hint"`
	MaxRows int      `json:"max_rows,omitempty" jsonschema:"walk and bulkwalk: at most this many rows (default 500, max 5000)"`
}

type Resolved struct {
	Input string `json:"input"`
	OID   string `json:"oid"`
	Name  string `json:"name,omitempty"`
}

type SNMPOutput struct {
	Device string `json:"device,omitempty"`
	snmp.Result
	Resolved    []Resolved `json:"resolved,omitempty"`
	DeviceError string     `json:"device_error,omitempty"`
	Untrusted   []string   `json:"_untrusted,omitempty"`
}

func registerSNMP(s *mcp.Server, d Deps) {
	in, err := jsonschema.For[SNMPInput](nil)
	if err != nil {
		panic(err)
	}
	in.Properties["action"].Enum = []any{"get", "walk", "bulkwalk", "resolve"}
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_snmp",
		Title: "Read a device over SNMP",
		Description: "Read-only SNMP (v2c or v3 authPriv; the version and credentials come from the server's rules, never from arguments).\n\n" +
			"get: up to 16 oids. walk / bulkwalk: every varbind under one root oid; prefer bulkwalk, it is faster. " +
			"Walks stop at the end of the subtree, at max_rows or near 60 KiB; then _truncation.hint gives the after value to continue with. " +
			"resolve: map MIB names to numeric OIDs and back, without a device. Names come from the IETF/IANA MIBs built in plus " +
			"any the operator loaded; numeric OIDs always work.\n\n" +
			"Rows are {oid, name, type, value}: printable strings as text, other octet strings as 0x hex, missing objects as null " +
			"with a warning. The community and USM subtrees (1.3.6.1.6.3.18, 1.3.6.1.6.3.15) are never read.\n\n" + UntrustedNote,
		InputSchema: in,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SNMPInput) (*mcp.CallToolResult, SNMPOutput, error) {
		var oids []string
		switch in.Action {
		case "get", "resolve":
			if len(in.OIDs) == 0 || len(in.OIDs) > snmp.MaxOIDs {
				return nil, SNMPOutput{}, fmt.Errorf("%s takes 1 to %d oids", in.Action, snmp.MaxOIDs)
			}
			for _, o := range in.OIDs {
				n, err := mib.OID(o)
				if err != nil {
					return nil, SNMPOutput{}, err
				}
				oids = append(oids, n)
			}
		case "walk", "bulkwalk":
			if in.MaxRows < 0 || in.MaxRows > snmp.MaxRows {
				return nil, SNMPOutput{}, fmt.Errorf("max_rows must be 1 to %d", snmp.MaxRows)
			}
			if in.OID == "" {
				return nil, SNMPOutput{}, fmt.Errorf("%s needs oid, the root of the subtree", in.Action)
			}
			root, err := mib.OID(in.OID)
			if err != nil {
				return nil, SNMPOutput{}, err
			}
			oids = []string{root}
			if in.After != "" {
				after, err := mib.OID(in.After)
				if err != nil {
					return nil, SNMPOutput{}, err
				}
				if !snmp.Within(after, root) {
					return nil, SNMPOutput{}, fmt.Errorf("after %s is not inside oid %s", after, root)
				}
				oids = append(oids, after)
			}
		default:
			return nil, SNMPOutput{}, fmt.Errorf("unknown action %q (want get, walk, bulkwalk or resolve)", in.Action)
		}
		if in.Action == "resolve" {
			out := SNMPOutput{}
			for i, o := range oids {
				out.Resolved = append(out.Resolved, Resolved{Input: in.OIDs[i], OID: o, Name: mib.Name(o)})
			}
			return nil, out, nil
		}
		for _, o := range oids {
			if err := snmp.Allowed(o); err != nil {
				d.deny("snmp_gate", in.Device, "", o, err)
				return nil, SNMPOutput{}, err
			}
		}

		g, err := d.gate(ctx, in.Device)
		if err != nil {
			return nil, SNMPOutput{}, err
		}
		t, err := d.snmpTarget(g)
		if err != nil {
			return nil, SNMPOutput{}, err
		}
		out := SNMPOutput{Device: g.dev.Name, Untrusted: []string{"rows"}}
		c, err := snmp.Dial(ctx, t)
		var res *snmp.Result
		if err == nil {
			defer c.Close()
			if in.Action == "get" {
				res, err = c.Get(oids)
			} else {
				after := ""
				if len(oids) == 2 {
					after = oids[1]
				}
				res, err = c.Walk(oids[0], after, in.Action == "bulkwalk", cmp.Or(in.MaxRows, snmp.DefaultRows))
			}
		}
		if res != nil {
			out.Result = *res
		}
		if err != nil {
			var n int
			out.DeviceError, n, _ = deviceError(err)
			out.Redactions += n
			out.Untrusted = append(out.Untrusted, "device_error")
		}
		return nil, out, nil
	})
}

// snmpTarget is a gated device's SNMP target, its credential read fresh.
func (d Deps) snmpTarget(g *gated) (snmp.Target, error) {
	s := g.dev.SNMP
	if s == nil {
		return snmp.Target{}, fmt.Errorf("device %s has no SNMP rule, so SNMP is disabled for it", g.dev.Name)
	}
	c, err := creds.ReadSNMP(d.Config.CredentialsDir, s.Ref, s.Version)
	if err != nil {
		return snmp.Target{}, err
	}
	return snmp.Target{Addr: g.addr, Port: s.Port, Cred: c, Timeout: d.Config.RequestTimeout}, nil
}

// sysUpTime reads sysUpTime.0, the network_status SNMP probe.
func (d Deps) sysUpTime(ctx context.Context, g *gated) (string, error) {
	t, err := d.snmpTarget(g)
	if err != nil {
		return "", err
	}
	c, err := snmp.Dial(ctx, t)
	if err != nil {
		return "", err
	}
	defer c.Close()
	r, err := c.Get([]string{snmp.SysUpTime})
	if err != nil {
		return "", err
	}
	if r.Rows[0].Value == nil {
		return "", fmt.Errorf("agent has no sysUpTime.0 (%s)", r.Rows[0].Type)
	}
	return fmt.Sprintf("sysUpTime %v", r.Rows[0].Value), nil
}
