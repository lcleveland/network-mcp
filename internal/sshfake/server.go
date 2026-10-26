package sshfake

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Options struct {
	Password      string        // accepted for every user (default "test-password")
	FailUser      string        // always fails auth
	AuthorizedKey ssh.PublicKey // if set, public-key auth with this key is accepted too
}

type Server struct {
	Addr       string // "127.0.0.1:port"
	Host       string
	Port       int
	KnownHosts string // known_hosts file pinning HostKey for Addr
	HostKey    ssh.PublicKey

	mu       sync.Mutex
	received []string
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// Start serves e over SSH on 127.0.0.1:0 with a fresh ed25519 host key until t ends.
func Start(t testing.TB, e *Engine, o Options) *Server {
	t.Helper()
	if o.Password == "" {
		o.Password = "test-password"
	}
	signer, pub := newKey(t)
	s := &Server{HostKey: pub, conns: map[net.Conn]struct{}{}}

	eng := *e
	eng.Log = func(line string) {
		s.mu.Lock()
		s.received = append(s.received, line)
		s.mu.Unlock()
		if e.Log != nil {
			e.Log(line)
		}
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() != o.FailUser && string(pw) == o.Password {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	if o.AuthorizedKey != nil {
		want := o.AuthorizedKey.Marshal()
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() != o.FailUser && string(k.Marshal()) == string(want) {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().(*net.TCPAddr)
	s.Addr, s.Host, s.Port = a.String(), a.IP.String(), a.Port
	s.KnownHosts = writeKnownHosts(t, s.Addr, pub)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[c] = struct{}{}
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serveConn(c, cfg, &eng)
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

// Received returns every line any session has received, in order.
func (s *Server) Received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.received...)
}

func (s *Server) serveConn(c net.Conn, cfg *ssh.ServerConfig, e *Engine) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	defer wg.Wait()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range creqs {
				req.Reply(req.Type != "exec" && req.Type != "subsystem", nil)
				if req.Type == "shell" {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if errors.Is(e.Serve(ch, ch), io.ErrUnexpectedEOF) {
							sc.Close()
							return
						}
						ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
						ch.Close()
					}()
				}
			}
		}()
	}
}

// WrongKnownHosts writes a known_hosts file pinning a fresh, unrelated key for addr.
func WrongKnownHosts(t testing.TB, addr string) string {
	t.Helper()
	_, pub := newKey(t)
	return writeKnownHosts(t, addr, pub)
}

func newKey(t testing.TB) (ssh.Signer, ssh.PublicKey) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, signer.PublicKey()
}

func writeKnownHosts(t testing.TB, addr string, pub ssh.PublicKey) string {
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(knownhosts.Line([]string{knownhosts.Normalize(addr)}, pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
