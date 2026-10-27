package tools

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/inventory"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/sshcli"
	"github.com/lcleveland/network-mcp/internal/version"
)

type StatusInput struct {
	Device string `json:"device,omitempty" jsonschema:"device name; omit for server health"`
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type StatusOutput struct {
	Version     string             `json:"version,omitempty"`
	Groups      []string           `json:"groups,omitempty"`
	Sources     []inventory.Health `json:"sources,omitempty"`
	Device      string             `json:"device,omitempty"`
	Address     string             `json:"address,omitempty"`
	Checks      []Check            `json:"checks,omitempty"`
	Prompt      string             `json:"prompt,omitempty"`
	DeviceError string             `json:"device_error,omitempty"`
	Untrusted   []string           `json:"_untrusted,omitempty"`
	Redactions  int                `json:"_redactions,omitempty"`
}

func registerStatus(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_status",
		Title: "Server and device connectivity check",
		Description: "Without device: the server version, enabled tool groups and the health of each inventory source.\n\n" +
			"With device: each connect check in order (management-prefix gate, TCP, pinned host key, read-credential auth, " +
			"prompt detected), stopping at the first failure. It runs no CLI command. " +
			"Call this first when network_show fails.\n\n" + UntrustedNote,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in StatusInput) (*mcp.CallToolResult, StatusOutput, error) {
		if in.Device == "" {
			var groups []string
			for _, g := range config.Groups {
				if d.Config.Enabled(g) {
					groups = append(groups, g)
				}
			}
			return nil, StatusOutput{Version: version.Version, Groups: groups, Sources: d.Inv.Health(ctx)}, nil
		}
		g, err := d.gate(ctx, in.Device)
		if g == nil {
			return nil, StatusOutput{}, err
		}
		out := StatusOutput{Device: g.dev.Name, Address: g.dev.Address}
		field := func(s string, max int) string {
			s, n := output.Field(s, max)
			out.Redactions += n
			return s
		}
		check := func(name string, err error) bool {
			c := Check{Name: name, OK: err == nil}
			if err != nil {
				c.Detail = field(err.Error(), output.LongCap)
			}
			out.Checks = append(out.Checks, c)
			return err == nil
		}

		// name the gate that refused, in the order inventory.Gate runs them
		gateName := "management_prefix"
		switch {
		case !g.dev.OptedIn:
			gateName = "opt_in"
		case g.dev.Unreachable != "":
			gateName = "reachable"
		}
		if !check(gateName, err) {
			return nil, out, nil
		}
		ctx, cancel := context.WithTimeout(ctx, d.Config.RequestTimeout)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(g.addr.String(), strconv.Itoa(g.dev.Port)))
		if !check("tcp", err) {
			return nil, out, nil
		}
		conn.Close()

		ses, err := d.open(ctx, g)
		var oe *sshcli.OpenError
		if errors.As(err, &oe) {
			// each stage that was passed is OK; the failing one carries the device's error
			for _, st := range []sshcli.Stage{sshcli.StageHostKey, sshcli.StageAuth, sshcli.StagePrompt} {
				if st == oe.Stage || (oe.Stage == sshcli.StageConnect && st == sshcli.StageHostKey) {
					out.Checks = append(out.Checks, Check{Name: string(st), OK: false})
					break
				}
				check(string(st), nil)
			}
			out.DeviceError = field(oe.Err.Error(), output.LongCap)
			out.Untrusted = []string{"device_error"}
			return nil, out, nil
		}
		if err != nil { // the read credential itself is unusable
			check("credential", err)
			return nil, out, nil
		}
		defer ses.Close()
		for _, st := range []sshcli.Stage{sshcli.StageHostKey, sshcli.StageAuth, sshcli.StagePrompt} {
			check(string(st), nil)
		}
		out.Prompt = field(ses.Prompt(), output.FieldCap)
		out.Untrusted = []string{"prompt"}
		return nil, out, nil
	})
}
