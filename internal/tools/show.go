package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/gate"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshcli"
)

type ShowInput struct {
	Device  string   `json:"device" jsonschema:"device name from the inventory"`
	Getter  string   `json:"getter,omitempty" jsonschema:"a NAPALM-named getter, mapped to the device platform's command; give getter or command, not both"`
	Command string   `json:"command,omitempty" jsonschema:"a read command with its first keyword in full: show, display, dir, ping or traceroute. No abbreviations, no pipes"`
	Include []string `json:"include,omitempty" jsonschema:"keep only lines matching any of these RE2 patterns (at most 8 of 256 bytes)"`
	Exclude []string `json:"exclude,omitempty" jsonschema:"drop lines matching any of these RE2 patterns (at most 8 of 256 bytes)"`
	Section string   `json:"section,omitempty" jsonschema:"keep lines matching this RE2 pattern plus the more-indented lines under each; applied before include and exclude"`
}

type ShowOutput struct {
	Device      string             `json:"device"`
	Command     string             `json:"command"`
	Parsed      bool               `json:"parsed"`
	Output      string             `json:"output,omitempty"`
	Data        any                `json:"data,omitempty"`
	DeviceError string             `json:"device_error,omitempty"`
	Untrusted   []string           `json:"_untrusted"`
	Redactions  int                `json:"_redactions"`
	Truncation  *output.Truncation `json:"_truncation,omitempty"`
}

func registerShow(s *mcp.Server, d Deps) {
	in, err := jsonschema.For[ShowInput](nil)
	if err != nil {
		panic(err)
	}
	for _, n := range platform.GetterNames(d.Config.File.Platforms) {
		in.Properties["getter"].Enum = append(in.Properties["getter"].Enum, n)
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_show",
		Title: "Run a read command on a device",
		Description: "Run one read-only CLI command on a device over SSH: a getter (facts, interfaces, routes, ...; " +
			"the server picks the platform's command) or a free-form command.\n\n" +
			"The first keyword must be written in full (show, display, dir, ping, traceroute); abbreviations, " +
			"pipes and config-dumping commands are refused before anything reaches the device. " +
			"Use section, include and exclude instead of pipes. NX-OS output comes back as JSON in data " +
			"(parsed: true) when it fits and no filter is given; everything else is raw text in output. " +
			"Secrets are always replaced with <redacted>; output over 60 KiB is cut and _truncation says how to narrow it. " +
			"Use network_status first if the device cannot be reached.\n\n" + UntrustedNote,
		InputSchema: in,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ShowInput) (*mcp.CallToolResult, ShowOutput, error) {
		dev, err := d.Inv.Get(ctx, in.Device)
		if err != nil {
			return nil, ShowOutput{}, err
		}
		var ok bool
		p := platform.Resolve(dev.Platform, d.Config.File.Platforms)
		raw := in.Command
		switch {
		case (in.Getter == "") == (in.Command == ""):
			return nil, ShowOutput{}, errors.New("give exactly one of getter or command")
		case in.Getter != "":
			if raw, ok = p.Getters[in.Getter]; !ok {
				avail := "none"
				if len(p.Getters) > 0 {
					avail = strings.Join(slices.Sorted(maps.Keys(p.Getters)), ", ")
				}
				return nil, ShowOutput{}, fmt.Errorf("getter %q is not available for %s (platform %q); available: %s. Use command instead", in.Getter, dev.Name, dev.Platform, avail)
			}
		}
		cmd, err := gate.Check(raw, p.Gate)
		if err != nil {
			d.deny("read_gate", in.Device, "", raw, err)
			return nil, ShowOutput{}, err
		}
		f, err := output.NewFilter(in.Include, in.Exclude, in.Section)
		if err != nil {
			return nil, ShowOutput{}, err
		}
		g, err := d.gate(ctx, in.Device)
		if err != nil {
			return nil, ShowOutput{}, err
		}
		out := ShowOutput{Device: g.dev.Name, Command: cmd, Untrusted: []string{"output"}}
		ctx, cancel := context.WithTimeout(ctx, d.Config.RequestTimeout)
		defer cancel()
		ses, err := d.open(ctx, g)
		if err != nil {
			return failed(out, err)
		}
		defer ses.Close()
		nxos := g.plat.Driver == platform.NXOS
		if nxos {
			cmd += " | json" // after the gate, which refuses a user's pipe
		}
		raw, err = ses.Run(ctx, cmd)
		limited := errors.Is(err, sshcli.ErrDeviceLimit)
		if err != nil && !limited {
			return failed(out, err)
		}
		if v, ok := decodeJSON(raw, nxos && !limited); ok {
			v, n := output.RedactJSON(v)
			if b, _ := json.Marshal(v); !f.Active() && len(b) <= output.MaxResult-output.Envelope {
				out.Data, out.Parsed, out.Redactions, out.Untrusted = v, true, n, []string{"data"}
				return nil, out, nil
			}
			// too big or filtered: the redacted JSON, indented, goes through the text pipeline
			b, _ := json.MarshalIndent(v, "", " ")
			raw, out.Redactions = string(b), n
		}
		text, n, tr := f.Text(raw, limited)
		out.Output, out.Redactions, out.Truncation = text, out.Redactions+n, tr
		return nil, out, nil
	})
}

// decodeJSON keeps numbers exact; anything but one JSON value is not JSON.
func decodeJSON(s string, try bool) (any, bool) {
	if !try {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return nil, false
	}
	return v, true
}

func failed(out ShowOutput, err error) (*mcp.CallToolResult, ShowOutput, error) {
	out.DeviceError, out.Redactions, out.Untrusted = deviceError(err)
	return nil, out, nil
}

// deviceError is the device_error field, its redaction count and _untrusted.
func deviceError(err error) (string, int, []string) {
	s, n := output.Field(err.Error(), output.LongCap)
	return s, n, []string{"device_error"}
}
