package export

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/server"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/lcleveland/network-mcp/internal/sshfake"
)

// serve file:// in process: the default file transport execs git-receive-pack
func init() { client.InstallProtocol("file", server.DefaultServer) }

func TestGit(t *testing.T) {
	base := t.TempDir()
	bare := filepath.Join(base, "remote.git")
	if _, err := git.PlainInit(bare, true); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(base, "push"), []byte(`{"token":"fake-token-secret"}`), 0o400)
	g := &Git{Name: "repo", Path: filepath.Join(base, "repo"), Branch: "main", Remote: "file://" + bare, Credential: "push", CredDir: base}
	ctx := context.Background()
	run := NewArtifact("dev1", "running", []byte("hostname dev1\n"), true)
	start := NewArtifact("dev1", "startup", []byte("hostname dev1\n"), true)

	rs, err := g.Put(ctx, []Artifact{run, start}, "test backup\n\nMCP-Session: s-1")
	if err != nil || len(rs) != 2 || !rs[0].Changed || !rs[1].Changed || rs[0].Ref != rs[1].Ref {
		t.Fatalf("first: %v %v", rs, err)
	}
	repo := must(git.PlainOpen(g.Path))
	c := must(repo.CommitObject(plumbing.NewHash(rs[0].Ref)))
	if c.Message != "test backup\n\nMCP-Session: s-1" || c.Author.Name != "network-mcp" {
		t.Fatalf("commit: %q %v", c.Message, c.Author)
	}
	if r, err := must(git.PlainOpen(bare)).Reference("refs/heads/main", true); err != nil || r.Hash().String() != rs[0].Ref {
		t.Fatalf("pushed: %v %v", r, err)
	}

	again, err := g.Put(ctx, []Artifact{run, start}, "again")
	if err != nil || again[0].Changed || again[1].Changed || again[0].Ref != rs[0].Ref {
		t.Fatalf("repeat: %v %v", again, err)
	}
	next, err := g.Put(ctx, []Artifact{NewArtifact("dev1", "running", []byte("hostname dev2\n"), true), start}, "edit")
	if err != nil || !next[0].Changed || next[1].Changed || next[0].Ref == rs[0].Ref || next[1].Ref != next[0].Ref {
		t.Fatalf("change: %v %v", next, err)
	}
	if h := must(repo.CommitObject(plumbing.NewHash(next[0].Ref))); h.ParentHashes[0].String() != rs[0].Ref {
		t.Fatal("not a child of the first commit")
	}

	// a failed push keeps the commit and returns every receipt
	g.Remote = "file://" + filepath.Join(base, "missing.git")
	rs, err = g.Put(ctx, []Artifact{NewArtifact("dev1", "running", []byte("hostname dev3\n"), true)}, "x")
	if err == nil || len(rs) != 1 || !rs[0].Changed || strings.Contains(err.Error(), "fake") {
		t.Fatalf("failed push: %v %v", rs, err)
	}
	if h, _ := repo.Head(); h.Hash().String() != rs[0].Ref {
		t.Fatal("local commit lost")
	}
}

func TestGitSSHPinned(t *testing.T) {
	base := t.TempDir()
	fake := sshfake.Start(t, &sshfake.Engine{}, sshfake.Options{})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk := must(ssh.MarshalPrivateKey(priv, ""))
	key := strings.ReplaceAll(string(pem.EncodeToMemory(blk)), "\n", `\n`)
	os.WriteFile(filepath.Join(base, "push"), []byte(`{"private_key":"`+key+`"}`), 0o400)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey := must(ssh.NewPublicKey(other))
	wrong := filepath.Join(base, "wrong_hosts")
	os.WriteFile(wrong, []byte(knownhosts.Line([]string{knownhosts.Normalize(fake.Addr)}, otherKey)+"\n"), 0o600)
	empty := filepath.Join(base, "empty_hosts")
	os.WriteFile(empty, nil, 0o600)

	put := func(kh string) error {
		g := &Git{Name: "repo", Path: filepath.Join(base, "repo"), Branch: "main", Remote: "ssh://git@" + fake.Addr + "/r.git",
			Credential: "push", CredDir: base, KnownHosts: kh}
		_, err := g.Put(context.Background(), []Artifact{NewArtifact("dev1", "running", []byte("x\n"), true)}, "r")
		if err != nil && strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("error leaks the key: %v", err)
		}
		return err
	}
	for _, kh := range []string{wrong, empty} {
		if err := put(kh); err == nil || !strings.Contains(err.Error(), "knownhosts") {
			t.Errorf("%s: %v, want a host key refusal", filepath.Base(kh), err)
		}
	}
	if err := put(""); err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("no known_hosts: %v", err)
	}
	// the pinned key passes the host check; the fake then refuses the login
	if err := put(fake.KnownHosts); err == nil || strings.Contains(err.Error(), "knownhosts") || !strings.Contains(err.Error(), "authenticate") {
		t.Errorf("pinned: %v", err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
