// Package sshcli is the generic SSH driver: scrapligo v1 over its pure-Go
// "standard" transport, a pinned known_hosts file, prompt detection and pager
// answering. It sends exactly the commands it is given; gating is the
// caller's job.
package sshcli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/scrapli/scrapligo/driver/generic"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/util"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/lcleveland/network-mcp/internal/creds"
)

// MaxRead caps one raw read from a device.
const MaxRead = 16 << 20

// scrapligo's default prompt, widened to 63-character hostnames.
var promptPattern = regexp.MustCompile(`(?im)^[a-z\d.\-@()/:_]{1,63}[#>$]\s*$`)

var (
	pagerPattern = regexp.MustCompile(`(?i)[ \t]*(--\s*more\s*--|press any key[^\n]*)\s*$`)
	// devices erase the pager text with backspaces, spaces and backspaces
	erasePattern = regexp.MustCompile(`\x08+ *\x08*`)
)

type Target struct {
	Addr       netip.Addr
	Port       int
	KnownHosts string
	Cred       creds.Cred
	Timeout    time.Duration
}

// Stage says how far a failed Open got, for network_status.
type Stage string

const (
	StageConnect Stage = "connect"
	StageHostKey Stage = "host_key"
	StageAuth    Stage = "auth"
	StagePrompt  Stage = "prompt"
)

type OpenError struct {
	Stage Stage
	Err   error
}

func (e *OpenError) Error() string { return string(e.Stage) + ": " + e.Err.Error() }
func (e *OpenError) Unwrap() error { return e.Err }

type Session struct {
	d      *generic.Driver
	prompt string
}

// Open connects, authenticates and waits for the first prompt without
// sending anything.
func Open(ctx context.Context, t Target) (*Session, error) {
	host := t.Addr.String()
	if t.Addr.Is6() {
		host = "[" + host + "]" // scrapligo dials host:port
	}
	opts := []util.Option{
		options.WithTransportType("standard"),
		options.WithSSHKnownHostsFile(t.KnownHosts),
		options.WithPort(t.Port),
		options.WithAuthUsername(t.Cred.Username),
		options.WithTimeoutSocket(t.Timeout),
		options.WithTimeoutOps(t.Timeout),
		options.WithPromptPattern(promptPattern),
	}
	if t.Cred.PrivateKey != "" {
		opts = append(opts, options.WithStandardTransportPrivateKeyBytes([]byte(t.Cred.PrivateKey), ""))
	} else {
		opts = append(opts, options.WithAuthPassword(t.Cred.Password))
	}
	d, err := generic.NewDriver(host, opts...)
	if err != nil {
		return nil, &OpenError{StageConnect, err}
	}
	if err := d.Open(); err != nil {
		return nil, &OpenError{classify(err), err}
	}
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	b, err := d.Channel.ReadUntilPrompt(ctx)
	if err != nil {
		d.Close()
		return nil, &OpenError{StagePrompt, fmt.Errorf("no prompt detected: %w", err)}
	}
	m := promptPattern.FindAll(b, -1)
	return &Session{d: d, prompt: strings.TrimSpace(string(m[len(m)-1]))}, nil
}

func classify(err error) Stage {
	var ke *knownhosts.KeyError
	switch {
	case errors.As(err, &ke):
		return StageHostKey
	case strings.Contains(err.Error(), "unable to authenticate"):
		return StageAuth
	}
	return StageConnect
}

func (s *Session) Prompt() string { return s.prompt }

func (s *Session) Close() { s.d.Close() }

// Run sends one command and returns its output without the echo, pager
// prompts or the trailing prompt. Paging is never turned off (on some
// platforms that is a config change); pager prompts are answered with a space.
func (s *Session) Run(ctx context.Context, cmd string) (string, error) {
	if err := s.d.Channel.WriteAndReturn([]byte(cmd), false); err != nil {
		return "", err
	}
	var buf []byte
	for {
		if ctx.Err() != nil {
			return "", fmt.Errorf("timed out waiting for the prompt after %d bytes", len(buf))
		}
		b, err := s.d.Channel.Read()
		if err != nil {
			return "", err
		}
		if b == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		buf = append(buf, b...)
		if len(buf) > MaxRead {
			return "", fmt.Errorf("output exceeds %d bytes", MaxRead)
		}
		last := buf[strings.LastIndexByte(string(buf), '\n')+1:]
		if loc := pagerPattern.FindIndex(last); loc != nil {
			buf = buf[:len(buf)-len(last)+loc[0]]
			if err := s.d.Channel.Write([]byte(" "), false); err != nil {
				return "", err
			}
			continue
		}
		if strings.TrimSpace(string(last)) == s.prompt {
			return clean(string(buf[:len(buf)-len(last)]), cmd), nil
		}
	}
}

func clean(out, cmd string) string {
	out = erasePattern.ReplaceAllString(out, "")
	if first, rest, ok := strings.Cut(out, "\n"); ok && strings.HasSuffix(strings.TrimSpace(first), cmd) {
		out = rest
	}
	return strings.TrimRight(out, "\n ")
}
