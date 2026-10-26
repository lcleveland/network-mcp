package sshcli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

func target(s *sshfake.Server, user string) Target {
	return Target{
		Addr: netip.MustParseAddr(s.Host), Port: s.Port, KnownHosts: s.KnownHosts,
		Cred: creds.Cred{Username: user, Password: "test-password"}, Timeout: 5 * time.Second,
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
