// Command network-mcp is an MCP server that reads network devices over SSH and SNMP.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/lcleveland/network-mcp/internal/audit"
	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/inventory"
	"github.com/lcleveland/network-mcp/internal/mib"
	"github.com/lcleveland/network-mcp/internal/server"
	"github.com/lcleveland/network-mcp/internal/sshcli"
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
	if len(args) > 0 && args[0] == "hostkey" {
		return hostkey(os.Stdout, args[1:])
	}
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

// hostkey prints the host key ADDR[:PORT] presents, for an operator to check
// on the device before adding the known_hosts line. It writes no file.
func hostkey(w io.Writer, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: network-mcp hostkey ADDR[:PORT]")
	}
	ap, err := netip.ParseAddrPort(args[0])
	if err != nil {
		a, err2 := netip.ParseAddr(args[0])
		if err2 != nil {
			return fmt.Errorf("hostkey: %q is not an IP address or IP:port", args[0])
		}
		ap = netip.AddrPortFrom(a, 22)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	k, err := sshcli.Offered(ctx, ap.Addr(), int(ap.Port()))
	if err != nil {
		return fmt.Errorf("hostkey: %w", err)
	}
	fmt.Fprintln(w, "# check on the device before pinning; this is what the network presented")
	fmt.Fprintln(w, "#", ssh.FingerprintSHA256(k))
	if kd := sshcli.KeyData(k); kd != "" {
		fmt.Fprintln(w, "# IOS: show crypto key mypubkey rsa, Key Data:")
		for l := range strings.SplitSeq(kd, "\n") {
			fmt.Fprintln(w, "#  ", l)
		}
	}
	fmt.Fprintln(w, knownhosts.Line([]string{knownhosts.Normalize(ap.String())}, k))
	return nil
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
	if err := mib.Load(cfg.MIBDirs...); err != nil {
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
