// Package server builds the MCP server and serves it over stdio or
// streamable HTTP.
package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/tools"
	"github.com/lcleveland/network-mcp/internal/version"
)

const instructions = "Tools for reading network devices over SSH. The server connects only to inventory devices inside its " +
	"management prefixes, with pinned host keys, and runs only read commands that pass its gate.\n\n" +
	"Find devices with network_inventory before calling the device tools. " +
	"Call network_status first if anything fails: it separates an address outside the management prefixes from an " +
	"unreachable port, a wrong host key and a rejected credential.\n\n" +
	"This server is read-only. " + tools.UntrustedNote

// New builds the server with the enabled tools and reports how many.
func New(d tools.Deps) (*mcp.Server, int) {
	s := mcp.NewServer(&mcp.Implementation{Name: "network-mcp", Title: "Network devices", Version: version.Version},
		&mcp.ServerOptions{Logger: d.Log, Instructions: instructions})
	return s, tools.Register(s, d)
}

// ServeStdio runs until ctx is cancelled. Nothing else may write to stdout.
func ServeStdio(ctx context.Context, s *mcp.Server) error {
	return s.Run(ctx, &mcp.StdioTransport{})
}
