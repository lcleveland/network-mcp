package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/gate"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/sshcli"
)

type ShowInput struct {
	Device  string   `json:"device" jsonschema:"device name from the inventory"`
	Command string   `json:"command" jsonschema:"a read command with its first keyword in full: show, display, dir, ping or traceroute. No abbreviations, no pipes"`
	Include []string `json:"include,omitempty" jsonschema:"keep only lines matching any of these RE2 patterns (at most 8 of 256 bytes)"`
	Exclude []string `json:"exclude,omitempty" jsonschema:"drop lines matching any of these RE2 patterns (at most 8 of 256 bytes)"`
	Section string   `json:"section,omitempty" jsonschema:"keep lines matching this RE2 pattern plus the more-indented lines under each; applied before include and exclude"`
}

type ShowOutput struct {
	Device      string             `json:"device"`
	Command     string             `json:"command"`
	Parsed      bool               `json:"parsed"`
	Output      string             `json:"output,omitempty"`
	DeviceError string             `json:"device_error,omitempty"`
	Untrusted   []string           `json:"_untrusted"`
	Redactions  int                `json:"_redactions"`
	Truncation  *output.Truncation `json:"_truncation,omitempty"`
}

func registerShow(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_show",
		Title: "Run a read command on a device",
		Description: "Run one read-only CLI command on a device over SSH and return its raw text.\n\n" +
			"The first keyword must be written in full (show, display, dir, ping, traceroute); abbreviations, " +
			"pipes and config-dumping commands are refused before anything reaches the device. " +
			"Use section, include and exclude instead of pipes. Secrets are always replaced with <redacted>; " +
			"output over 60 KiB is cut and _truncation says how to narrow it. " +
			"Use network_status first if the device cannot be reached.\n\n" + UntrustedNote,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ShowInput) (*mcp.CallToolResult, ShowOutput, error) {
		cmd, err := gate.Check(in.Command)
		if err != nil {
			d.deny("read_gate", in.Device, "", in.Command, err)
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
		raw, err := ses.Run(ctx, cmd)
		limited := errors.Is(err, sshcli.ErrDeviceLimit)
		if err != nil && !limited {
			return failed(out, err)
		}
		out.Output, out.Redactions, out.Truncation = f.Text(raw, limited)
		return nil, out, nil
	})
}

func failed(out ShowOutput, err error) (*mcp.CallToolResult, ShowOutput, error) {
	out.DeviceError, out.Redactions = output.Field(err.Error(), output.LongCap)
	out.Untrusted = []string{"device_error"}
	return nil, out, nil
}
