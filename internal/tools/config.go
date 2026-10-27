package tools

import (
	"cmp"
	"context"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/output"
)

type ConfigInput struct {
	Action  string   `json:"action" jsonschema:"get: read the config"`
	Device  string   `json:"device" jsonschema:"device name from the inventory"`
	Source  string   `json:"source" jsonschema:"running or startup"`
	Include []string `json:"include,omitempty" jsonschema:"keep only lines matching any of these RE2 patterns (at most 8 of 256 bytes)"`
	Exclude []string `json:"exclude,omitempty" jsonschema:"drop lines matching any of these RE2 patterns (at most 8 of 256 bytes)"`
	Section string   `json:"section,omitempty" jsonschema:"keep lines matching this RE2 pattern plus the more-indented lines under each; applied before include and exclude"`
}

type ConfigOutput struct {
	Device      string             `json:"device"`
	Source      string             `json:"source"`
	Output      string             `json:"output,omitempty"`
	DeviceError string             `json:"device_error,omitempty"`
	Untrusted   []string           `json:"_untrusted"`
	Redactions  int                `json:"_redactions"`
	Truncation  *output.Truncation `json:"_truncation,omitempty"`
}

func registerConfig(s *mcp.Server, d Deps) {
	in, err := jsonschema.For[ConfigInput](nil)
	if err != nil {
		panic(err)
	}
	in.Properties["action"].Enum = []any{"get"}
	in.Properties["source"].Enum = []any{"running", "startup"}
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_config",
		Title: "Read a device's running or startup config",
		Description: "Read a device's running or startup configuration over SSH (action get). The server picks the " +
			"command; IOS, IOS-XE and NX-OS have one built in, other platforms need platforms.<value>.config in the config file.\n\n" +
			"Secrets are always replaced with <redacted> and _redactions counts them. The patterns are Cisco-shaped; on other " +
			"platforms only a catch-all for password, secret, key, community, psk and passphrase values applies, so use a " +
			"read-only device account. Use section (e.g. \"^interface \"), include and exclude to narrow; they run before " +
			"the 60 KiB cut, and _truncation says when output was cut.\n\n" + UntrustedNote,
		InputSchema: in,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ConfigInput) (*mcp.CallToolResult, ConfigOutput, error) {
		f, err := output.NewFilter(in.Include, in.Exclude, in.Section)
		if err != nil {
			return nil, ConfigOutput{}, err
		}
		g, cmd, err := d.configTarget(ctx, in.Device, in.Source)
		if err != nil {
			return nil, ConfigOutput{}, err
		}
		out := ConfigOutput{Device: g.dev.Name, Source: in.Source, Untrusted: []string{"output"}}
		raw, err := d.fetch(ctx, g, cmd)
		if err != nil {
			out.DeviceError, out.Redactions, out.Untrusted = deviceError(err)
			return nil, out, nil
		}
		out.Output, out.Redactions, out.Truncation = f.Text(raw, false)
		return nil, out, nil
	})
}

// FetchConfig returns a device's unredacted running or startup config, for
// export and change hashing; it never reaches a tool result. ref overrides
// the read credential ref when set. Output over sshcli.MaxRead is an error.
func (d Deps) FetchConfig(ctx context.Context, device, source, ref string) (string, error) {
	g, cmd, err := d.configTarget(ctx, device, source)
	if err != nil {
		return "", err
	}
	g.ref = cmp.Or(ref, g.ref)
	return d.fetch(ctx, g, cmd)
}

// configTarget gates the device and picks its config command, which comes
// from the platform table, never from the caller.
func (d Deps) configTarget(ctx context.Context, device, source string) (*gated, string, error) {
	g, err := d.gate(ctx, device)
	if err != nil {
		return nil, "", err
	}
	cmd := map[string]string{"running": g.plat.Config.Running, "startup": g.plat.Config.Startup}[source]
	switch {
	case source != "running" && source != "startup":
		return nil, "", fmt.Errorf("source must be running or startup, not %q", source)
	case cmd == "":
		return nil, "", fmt.Errorf("%s (platform %q) has no %s config command; set platforms.%s.config.%s in the config file",
			g.dev.Name, g.dev.Platform, source, cmp.Or(g.dev.Platform, "<platform>"), source)
	}
	return g, cmd, nil
}

// fetch runs one command in its own session. Hitting the device limit is an
// error, so no caller sees a partial config.
func (d Deps) fetch(ctx context.Context, g *gated, cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.Config.RequestTimeout)
	defer cancel()
	ses, err := d.open(ctx, g)
	if err != nil {
		return "", err
	}
	defer ses.Close()
	out, err := ses.Run(ctx, cmd)
	if err != nil {
		return "", err
	}
	return out, nil
}
