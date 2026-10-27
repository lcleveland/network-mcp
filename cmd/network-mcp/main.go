// Command network-mcp is an MCP server that reads network devices over SSH.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/lcleveland/network-mcp/internal/audit"
	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/inventory"
	"github.com/lcleveland/network-mcp/internal/server"
	"github.com/lcleveland/network-mcp/internal/tools"
	"github.com/lcleveland/network-mcp/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "network-mcp:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string) error {
	d, err := setup(args, getenv)
	if d == nil || err != nil {
		return err
	}
	d.Log.Info("starting", "version", version.Version, "config", d.Config)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, n := server.New(*d)
	d.Log.Info("registered tools", "count", n)
	if d.Config.HTTP {
		return server.ServeHTTP(ctx, d.Config, s, d.Log)
	}
	return server.ServeStdio(ctx, s)
}

// setup validates everything startup needs; nil Deps means --version.
func setup(args []string, getenv func(string) string) (*tools.Deps, error) {
	cfg, err := config.Parse(args, getenv)
	if err != nil {
		return nil, err
	}
	if cfg.ShowVersion {
		fmt.Println(version.Version)
		return nil, nil
	}
	inv, err := inventory.Load(cfg)
	if err != nil {
		return nil, err
	}
	// every device is SSH until other drivers exist
	if (len(cfg.File.Sources) > 0 || cfg.AllowAdhoc) && cfg.KnownHosts == "" {
		return nil, errors.New("--known-hosts (or NETWORK_MCP_KNOWN_HOSTS) is required when any device uses SSH")
	}
	// stdout belongs to the stdio transport; logs and audit go to stderr.
	return &tools.Deps{
		Config: cfg,
		Inv:    inv,
		Audit:  audit.New(os.Stderr),
		Log:    slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})),
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}, nil
}
