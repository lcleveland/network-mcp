package sshfake

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var dev1 = Engine{
	Hostname: "dev1",
	Commands: map[string]string{"show version": "Cisco IOS Software, Version 15.2\n"},
}

type shell struct {
	t   *testing.T
	in  io.Writer
	out *bufio.Reader
}

func dial(t *testing.T, s *Server, user, knownHostsPath string) (*ssh.Client, error) {
	hk, err := knownhosts.New(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	cc, chans, reqs, err := ssh.NewClientConn(c, s.Addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password("test-password")},
		HostKeyCallback: hk,
	})
	if err != nil {
		c.Close()
		return nil, err
	}
	cl := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { cl.Close() })
	return cl, nil
}

func open(t *testing.T, s *Server) *shell {
	cl, err := dial(t, s, "admin", s.KnownHosts)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("vt100", 40, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatal(err)
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	sh := &shell{t, in, bufio.NewReader(out)}
	sh.until("dev1#")
	return sh
}

// until reads up to and including suffix and returns what it read.
func (sh *shell) until(suffix string) string {
	sh.t.Helper()
	var b []byte
	for !bytes.HasSuffix(b, []byte(suffix)) {
		c, err := sh.out.ReadByte()
		if err != nil {
			sh.t.Fatalf("waiting for %q after %q: %v", suffix, b, err)
		}
		b = append(b, c)
	}
	return string(b)
}

func (sh *shell) send(line string) string {
	sh.t.Helper()
	io.WriteString(sh.in, line+"\n")
	return sh.until("dev1#")
}

func TestCommands(t *testing.T) {
	s := Start(t, &dev1, Options{})
	sh := open(t, s)
	if got, want := sh.send("show version"), "show version\nCisco IOS Software, Version 15.2\ndev1#"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := sh.send("show bogus"); !strings.Contains(got, "% Invalid input") {
		t.Errorf("unknown command: %q", got)
	}
	sh.send("")
	if got, want := s.Received(), []string{"show version", "show bogus", ""}; !slices.Equal(got, want) {
		t.Errorf("Received() = %q, want %q", got, want)
	}
}

func TestWrongHostKey(t *testing.T) {
	s := Start(t, &dev1, Options{})
	if _, err := dial(t, s, "admin", WrongKnownHosts(t, s.Addr)); err == nil || !strings.Contains(err.Error(), "key mismatch") {
		t.Fatalf("want host key mismatch, got %v", err)
	}
}

func TestFailUser(t *testing.T) {
	s := Start(t, &dev1, Options{FailUser: "nobody"})
	if _, err := dial(t, s, "nobody", s.KnownHosts); err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("want auth failure, got %v", err)
	}
}

func TestPager(t *testing.T) {
	e := dev1
	e.PagerPrompt, e.PagerLines = " --More-- ", 2
	e.Commands = map[string]string{"show log": "l1\nl2\nl3\n"}
	sh := open(t, Start(t, &e, Options{}))
	io.WriteString(sh.in, "show log\n")
	if got := sh.until(" --More-- "); got != "show log\nl1\nl2\n --More-- " {
		t.Errorf("first page %q", got)
	}
	io.WriteString(sh.in, " ")
	if got := sh.until("dev1#"); !strings.HasSuffix(got, "l3\ndev1#") {
		t.Errorf("second page %q", got)
	}
}

func TestDropOn(t *testing.T) {
	e := dev1
	e.DropOn = "show version"
	sh := open(t, Start(t, &e, Options{}))
	io.WriteString(sh.in, "show version\n")
	b, err := io.ReadAll(sh.out)
	if err != nil || strings.Contains(string(b), "dev1#") || !strings.HasPrefix(string(b), "show version\nCisco") {
		t.Fatalf("got %q, %v", b, err)
	}
}

func TestEngine(t *testing.T) {
	var out bytes.Buffer
	e := Engine{Hostname: "dev1", Banner: "Authorized access only\n", Commands: map[string]string{"show clock": "12:00:00.000 UTC"}}
	if err := e.Serve(strings.NewReader("show clock\r\nshow clock\rexit\n"), &out); err != nil {
		t.Fatal(err)
	}
	want := "Authorized access only\ndev1#show clock\n12:00:00.000 UTC\ndev1#show clock\n12:00:00.000 UTC\ndev1#exit\n"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}
