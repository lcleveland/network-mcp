package export

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"

	"github.com/lcleveland/network-mcp/internal/creds"
)

// never read ~/.ssh/config: an ssh remote is exactly what the config says
func init() { gitssh.DefaultSSHConfig = nil }

// Git commits each batch to the repo at Path (initialised if missing) and,
// with Remote, pushes HEAD to Branch there.
type Git struct {
	Name, Path, Branch                      string
	Remote, Credential, CredDir, KnownHosts string

	mu sync.Mutex // one batch at a time per repo
}

// Put writes through Dir, then commits what differs from HEAD with message
// msg. A failed push keeps the commit and returns full receipts with the error.
func (g *Git) Put(ctx context.Context, as []Artifact, msg string) ([]Receipt, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	repo, err := git.PlainOpen(g.Path)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		repo, err = git.PlainInitWithOptions(g.Path, &git.PlainInitOptions{
			InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName(g.Branch)}})
	}
	if err != nil {
		return nil, err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	var tree *object.Tree
	if head, err := repo.Head(); err == nil {
		c, err := repo.CommitObject(head.Hash())
		if err != nil {
			return nil, err
		}
		if tree, err = c.Tree(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil, err
	}
	if _, err := (Dir{Name: g.Name, Root: g.Path}).Put(ctx, as, msg); err != nil {
		return nil, err
	}

	changed := make([]bool, len(as))
	for i, a := range as {
		rel, _ := a.Rel() // Dir.Put checked it
		if tree != nil {
			f, err := tree.File(rel)
			changed[i] = err != nil || f.Hash != plumbing.ComputeHash(plumbing.BlobObject, a.Body)
		} else {
			changed[i] = true
		}
		if changed[i] {
			if _, err := wt.Add(rel); err != nil {
				return nil, fmt.Errorf("%s: %w", rel, err)
			}
		}
	}
	if slices.Contains(changed, true) {
		sig := &object.Signature{Name: "network-mcp", Email: "network-mcp@localhost", When: time.Now()}
		if _, err := wt.Commit(msg, &git.CommitOptions{Author: sig}); err != nil {
			return nil, err
		}
	}
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	rs := make([]Receipt, len(as))
	for i := range as {
		rs[i] = Receipt{Destination: g.Name, Changed: changed[i], Ref: head.Hash().String()}
	}
	if g.Remote != "" { // also after no change, so an earlier failed push is retried
		if err := g.push(ctx, repo, head.Name()); err != nil {
			return rs, fmt.Errorf("committed locally, push failed: %w", err)
		}
	}
	return rs, nil
}

// push reads the credential ref now and pins an ssh remote's host key to
// KnownHosts; never ~/.ssh.
func (g *Git) push(ctx context.Context, repo *git.Repository, head plumbing.ReferenceName) error {
	ep, err := transport.NewEndpoint(g.Remote)
	if err != nil {
		return err
	}
	ssh := ep.Protocol == "ssh"
	user, secret, err := creds.GitPush(g.CredDir, g.Credential, ssh)
	if err != nil {
		return err
	}
	var auth transport.AuthMethod = &githttp.BasicAuth{Username: user, Password: secret}
	if ssh {
		if g.KnownHosts == "" { // NewKnownHostsDb with no file reads ~/.ssh/known_hosts
			return errors.New("an ssh remote needs known_hosts")
		}
		k, err := gitssh.NewPublicKeys(user, []byte(secret), "")
		if err != nil {
			return fmt.Errorf("credential ref %q: private_key does not parse", g.Credential)
		}
		db, err := gitssh.NewKnownHostsDb(g.KnownHosts)
		if err != nil {
			return fmt.Errorf("known_hosts: %w", err)
		}
		k.HostKeyCallback = db.HostKeyCallback()
		k.HostKeyAlgorithms = db.HostKeyAlgorithms(net.JoinHostPort(ep.Host, strconv.Itoa(cmp.Or(ep.Port, 22))))
		auth = k
	}
	err = git.NewRemote(repo.Storer, &gitconfig.RemoteConfig{Name: "origin", URLs: []string{g.Remote}}).PushContext(ctx, &git.PushOptions{
		RefSpecs: []gitconfig.RefSpec{gitconfig.RefSpec(head + ":" + plumbing.NewBranchReferenceName(g.Branch))},
		Auth:     auth,
	})
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil
	}
	return err
}
