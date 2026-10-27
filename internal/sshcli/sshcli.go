// Package sshcli holds the SSH drivers: scrapligo v1 over its pure-Go
// "standard" transport, a pinned known_hosts file, prompt detection and pager
// answering. The generic driver sends exactly the commands it is given; the
// IOS-XE and NX-OS drivers add only session-only terminal settings. Gating
// is the caller's job.
package sshcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/scrapli/scrapligo/driver/generic"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
	"github.com/scrapli/scrapligo/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/lcleveland/network-mcp/internal/creds"
)

// MaxRead caps one raw read from a device.
const MaxRead = 16 << 20

// ErrDeviceLimit comes with the first MaxRead bytes of an output that ran longer.
var ErrDeviceLimit = fmt.Errorf("output exceeds %d bytes", MaxRead)

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
	Driver     string // "iosxe", "nxos"; anything else is the generic driver
}

// drivers maps a driver to its embedded scrapligo platform and the
// session-only settings sent before the first command. Only these constants
// reach platform.NewPlatform, which would read a path or URL otherwise.
var drivers = map[string]struct {
	platform string
	setup    []string
}{
	"iosxe": {"cisco_iosxe", []string{"terminal width 512", "terminal length 0"}},
	"nxos":  {"cisco_nxos", []string{"terminal width 511", "terminal length 0"}},
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
	setup  []string // sent by the first Run, so Open sends nothing
}

// Open connects, authenticates and waits for the first prompt without
// sending anything. A platform driver takes its prompt patterns and failure
// strings from the scrapligo platform, but never changes privilege: an
// account landing at ">" reads at exec level.
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
	drv := drivers[t.Driver]
	d, err := newDriver(host, drv.platform, opts)
	if err != nil {
		return nil, &OpenError{StageConnect, err}
	}
	if err := d.Open(); err != nil {
		if ke := (*knownhosts.KeyError)(nil); errors.As(err, &ke) {
			err = hostKeyError{ke}
		}
		return nil, &OpenError{classify(err), err}
	}
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	b, err := d.Channel.ReadUntilPrompt(ctx)
	if err != nil {
		d.Close()
		return nil, &OpenError{StagePrompt, fmt.Errorf("no prompt detected: %w", err)}
	}
	m := d.Channel.PromptPattern.FindAll(b, -1)
	return &Session{d: d, prompt: strings.TrimSpace(string(m[len(m)-1])), setup: drv.setup}, nil
}

// newDriver builds the generic driver, or a platform's embedded one. The
// platform's network driver is never opened: its on-open and on-close
// acquire privilege with "enable".
func newDriver(host, plat string, opts []util.Option) (*generic.Driver, error) {
	if plat == "" {
		return generic.NewDriver(host, opts...)
	}
	p, err := platform.NewPlatform(plat, host, opts...)
	if err != nil {
		return nil, err
	}
	nd, err := p.GetNetworkDriver()
	if err != nil {
		return nil, err
	}
	return nd.Driver, nil
}

// hostKeyError words a known_hosts refusal without "key <word>", which the
// output redactor would blank ("key is unknown" read as "key <redacted> unknown").
type hostKeyError struct{ ke *knownhosts.KeyError }

func (e hostKeyError) Error() string {
	if len(e.ke.Want) == 0 {
		return "host key: not pinned in known_hosts"
	}
	return "host key: differs from the one pinned in known_hosts"
}

func (e hostKeyError) Unwrap() error { return e.ke }

// Offered returns the host key addr:port presents, stopping the handshake
// as soon as it arrives, so nothing is authenticated or sent. The key is
// trusted for nothing: it is shown for an operator to check on the device.
// The client defaults match Open's, so this is the key Open would check.
func Offered(ctx context.Context, addr netip.Addr, port int) (ssh.PublicKey, error) {
	ap := netip.AddrPortFrom(addr.Unmap(), uint16(port)).String()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ap)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	var key ssh.PublicKey
	_, _, _, err = ssh.NewClientConn(conn, ap, &ssh.ClientConfig{
		User: "network-mcp",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errors.New("stop after the host key")
		},
	})
	if key == nil {
		return nil, err
	}
	return key, nil
}

// KeyData formats an RSA key as IOS prints it under "Key Data:" in show
// crypto key mypubkey rsa: the DER public key in upper-case hex, eight
// 8-digit groups a line. Other key types return "".
func KeyData(k ssh.PublicKey) string {
	ck, ok := k.(ssh.CryptoPublicKey)
	if k.Type() != ssh.KeyAlgoRSA || !ok {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(ck.CryptoPublicKey())
	if err != nil {
		return ""
	}
	h := strings.ToUpper(hex.EncodeToString(der))
	var b strings.Builder
	for i := 0; i < len(h); i += 8 {
		switch {
		case i == 0:
		case i%64 == 0:
			b.WriteByte('\n')
		default:
			b.WriteByte(' ')
		}
		b.WriteString(h[i:min(i+8, len(h))])
	}
	return b.String()
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

// HostKey returns the SHA256 fingerprints of the keys known_hosts pins for
// addr:port, sorted and comma-joined, without dialing. Open accepts only
// these keys, so a plan can bind them.
func HostKey(knownHosts string, addr netip.Addr, port int) (string, error) {
	cb, err := knownhosts.New(knownHosts)
	if err != nil {
		return "", err
	}
	// a key nobody pins makes the callback list the pinned ones
	probe, _ := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	ap := netip.AddrPortFrom(addr.Unmap(), uint16(port))
	var ke *knownhosts.KeyError
	if err := cb(ap.String(), net.TCPAddrFromAddrPort(ap), probe); !errors.As(err, &ke) || len(ke.Want) == 0 {
		return "", fmt.Errorf("no host key is pinned for %s", ap)
	}
	var fps []string
	for _, k := range ke.Want {
		fps = append(fps, ssh.FingerprintSHA256(k.Key))
	}
	slices.Sort(fps)
	return strings.Join(slices.Compact(fps), ","), nil
}

func (s *Session) Prompt() string { return s.prompt }

func (s *Session) Close() { s.d.Close() }

// Run sends one command and returns its output without the echo, pager
// prompts or the trailing prompt. The generic driver never turns paging off
// (on some platforms that is a config change); pager prompts are answered
// with a space. A platform's failure string near the top of the output
// returns the output as the error.
func (s *Session) Run(ctx context.Context, cmd string) (string, error) {
	return s.Ask(ctx, cmd, nil)
}

// Ask is Run that answers the first question matching q, such as copy's
// "Destination filename [startup-config]?", with Enter (its default).
func (s *Session) Ask(ctx context.Context, cmd string, q *regexp.Regexp) (string, error) {
	for len(s.setup) > 0 {
		// the reply is ignored: a refused setting only leaves paging on
		if _, err := s.run(ctx, s.setup[0], nil); err != nil {
			return "", err
		}
		s.setup = s.setup[1:]
	}
	out, err := s.run(ctx, cmd, q)
	if err != nil {
		return out, err
	}
	// devices print the failure first; further down it is output, such as a log line
	lines := strings.SplitN(out, "\n", 4)
	head := strings.Join(lines[:min(3, len(lines))], "\n")
	for _, f := range s.d.FailedWhenContains {
		if strings.Contains(head, f) {
			return "", errors.New(out)
		}
	}
	return out, nil
}

func (s *Session) run(ctx context.Context, cmd string, q *regexp.Regexp) (string, error) {
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
			return clean(string(buf[:MaxRead]), cmd), ErrDeviceLimit
		}
		last := buf[bytes.LastIndexByte(buf, '\n')+1:]
		if loc := pagerPattern.FindIndex(last); loc != nil {
			buf = buf[:len(buf)-len(last)+loc[0]]
			if err := s.d.Channel.Write([]byte(" "), false); err != nil {
				return "", err
			}
			continue
		}
		if q != nil && q.Match(last) {
			q = nil
			if err := s.d.Channel.WriteReturn(); err != nil {
				return "", err
			}
			continue
		}
		if s.isPrompt(string(last)) {
			return clean(string(buf[:len(buf)-len(last)]), cmd), nil
		}
	}
}

// isPrompt is the session's prompt, or its config-mode form such as
// "dev1(config-if)#" while a change is applied.
// shortcut: assumes config mode keeps the whole hostname; check on hardware.
func (s *Session) isPrompt(l string) bool {
	l = strings.TrimSpace(l)
	base, priv := strings.CutSuffix(s.prompt, "#")
	mode, cfg := strings.CutPrefix(l, base+"(config")
	return l == s.prompt || priv && cfg && strings.HasSuffix(mode, ")#") && !strings.ContainsAny(mode, " \t")
}

func clean(out, cmd string) string {
	out = erasePattern.ReplaceAllString(out, "")
	if first, rest, ok := strings.Cut(out, "\n"); ok && strings.HasSuffix(strings.TrimSpace(first), cmd) {
		out = rest
	}
	return strings.TrimRight(out, "\n ")
}

// Pinned reports whether known_hosts holds a key for addr:port, without
// dialling: a probe key that matches nothing shows whether any key is wanted.
func Pinned(knownHosts string, addr netip.Addr, port int) bool {
	cb, err := knownhosts.New(knownHosts)
	if err != nil {
		return false
	}
	probe, _ := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	ap := netip.AddrPortFrom(addr, uint16(port))
	err = cb(ap.String(), net.TCPAddrFromAddrPort(ap), probe)
	var ke *knownhosts.KeyError
	return err == nil || errors.As(err, &ke) && len(ke.Want) > 0
}
