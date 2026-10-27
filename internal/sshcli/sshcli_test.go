package sshcli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

func target(s *sshfake.Server, user string) Target {
	return Target{
		Addr: netip.MustParseAddr(s.Host), Port: s.Port, KnownHosts: s.KnownHosts,
		Cred: creds.Cred{Username: user, Password: "test-password"}, Timeout: 5 * time.Second,
	}
}

func TestHostKey(t *testing.T) {
	s := sshfake.Start(t, &sshfake.Engine{Hostname: "dev1"}, sshfake.Options{})
	a := netip.MustParseAddr(s.Host)
	fp, err := HostKey(s.KnownHosts, a, s.Port)
	if err != nil || fp != ssh.FingerprintSHA256(s.HostKey) {
		t.Fatalf("%q %v", fp, err)
	}
	if _, err := HostKey(s.KnownHosts, a, s.Port+1); err == nil {
		t.Fatal("an unpinned port has a key")
	}
	if fp2, _ := HostKey(sshfake.WrongKnownHosts(t, s.Addr), a, s.Port); fp2 == fp || fp2 == "" {
		t.Fatalf("a different pin gave %q", fp2)
	}
}

func TestRun(t *testing.T) {
	var long strings.Builder
	for i := range 60 {
		fmt.Fprintf(&long, "line %d\n", i)
	}
	s := sshfake.Start(t, &sshfake.Engine{
		Hostname:    "dev1",
		Banner:      "authorised access only\n",
		Commands:    map[string]string{"show version": "Cisco IOS Software, Version 1.0\n", "show log": long.String()},
		PagerPrompt: " --More-- ",
	}, sshfake.Options{})

	ses, err := Open(context.Background(), target(s, "mcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer ses.Close()
	if ses.Prompt() != "dev1#" {
		t.Fatalf("prompt %q", ses.Prompt())
	}
	out, err := ses.Run(context.Background(), "show version")
	if err != nil || out != "Cisco IOS Software, Version 1.0" {
		t.Fatalf("%q %v", out, err)
	}
	out, err = ses.Run(context.Background(), "show log")
	if err != nil || out != strings.TrimSpace(long.String()) {
		t.Fatalf("paged output %q %v", out, err)
	}
	if got := s.Received(); len(got) < 2 || got[0] != "show version" || got[1] != "show log" {
		t.Fatalf("received %q", got)
	}
}

func TestPlatformDrivers(t *testing.T) {
	long := strings.Repeat("a", 62) + "1" // 63 characters
	for _, tc := range []struct {
		driver, host string
		profile      sshfake.Profile
		setup        []string
		failure      string
	}{
		{"iosxe", "dev1", sshfake.IOSXE, []string{"terminal width 512", "terminal length 0"}, "show bogus"},
		{"nxos", long, sshfake.NXOS, []string{"terminal width 511", "terminal length 0"}, "show bogus"},
		{"nxos", "dev1", sshfake.Profile{Prompt: ">", Invalid: "ERROR: no such command\n"}, []string{"terminal width 511", "terminal length 0"}, "show bogus"},
	} {
		s := sshfake.Start(t, &sshfake.Engine{
			Hostname: tc.host, Profile: tc.profile,
			Banner:   "user$\nlast$ \n", // not a prompt for either platform
			Commands: map[string]string{"show version": "line$\nsh$\ndev1>x\nend", "show log": "ok\nok\nok\nERROR: in a log line"},
		}, sshfake.Options{})
		tg := target(s, "mcp")
		tg.Driver = tc.driver
		ses, err := Open(context.Background(), tg)
		if err != nil {
			t.Fatalf("%s: %v", tc.driver, err)
		}
		if want := strings.TrimSpace(tc.host + tc.profile.Prompt); ses.Prompt() != want {
			t.Errorf("%s: prompt %q, want %q", tc.driver, ses.Prompt(), want)
		}
		if len(s.Received()) != 0 {
			t.Errorf("%s: Open sent %q", tc.driver, s.Received())
		}
		out, err := ses.Run(context.Background(), "show version")
		if err != nil || out != "line$\nsh$\ndev1>x\nend" {
			t.Errorf("%s: %q %v", tc.driver, out, err)
		}
		if out, err := ses.Run(context.Background(), "show log"); err != nil || !strings.HasSuffix(out, "log line") {
			t.Errorf("%s: a failure string deep in output: %q %v", tc.driver, out, err)
		}
		if _, err := ses.Run(context.Background(), tc.failure); err == nil || !strings.Contains(err.Error(), tc.profile.Invalid[:5]) {
			t.Errorf("%s: device failure: %v", tc.driver, err)
		}
		ses.Close()
		want := append(tc.setup, "show version", "show log", tc.failure)
		if got := s.Received(); !slices.Equal(got[:min(len(got), len(want))], want) || slices.Contains(got, "enable") {
			t.Errorf("%s: received %q, want %q", tc.driver, got, want)
		}
	}
}

func TestOpenFailures(t *testing.T) {
	s := sshfake.Start(t, &sshfake.Engine{Hostname: "dev1"}, sshfake.Options{FailUser: "nobody"})

	_, err := Open(context.Background(), target(s, "nobody"))
	if oe := (*OpenError)(nil); !errors.As(err, &oe) || oe.Stage != StageAuth {
		t.Fatalf("auth: %v", err)
	}

	tg := target(s, "mcp")
	tg.KnownHosts = sshfake.WrongKnownHosts(t, s.Addr)
	_, err = Open(context.Background(), tg)
	if oe := (*OpenError)(nil); !errors.As(err, &oe) || oe.Stage != StageHostKey {
		t.Fatalf("host key: %v", err)
	}
	if len(s.Received()) != 0 {
		t.Fatalf("nothing should reach the device: %q", s.Received())
	}
}
