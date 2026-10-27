package fixtures

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPreCommitHook plants a denylisted name in a throwaway repo using
// .githooks: the commit is refused, and a clean one goes through.
func TestPreCommitHook(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	hooks, err := filepath.Abs(filepath.Join("..", "..", ".githooks"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	git := func(args ...string) (string, error) {
		c := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.hooksPath=" + hooks}, args...)...)
		c.Dir, c.Env = dir, append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := c.CombinedOutput()
		return string(out), err
	}
	if out, err := git("init", "-q"); err != nil {
		t.Fatal(out)
	}
	os.WriteFile(filepath.Join(dir, DenylistFile), []byte("# real names\nacme-core-7\n"), 0o600)
	commit := func(name, body string) (string, error) {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
		if out, err := git("add", name); err != nil {
			t.Fatal(out)
		}
		return git("commit", "-q", "-m", name)
	}
	out, err := commit("planted.txt", "hostname ACME-CORE-7\n")
	if err == nil || !strings.Contains(out, "planted.txt adds a term") || strings.Contains(strings.ToLower(out), "acme-core-7") {
		t.Fatalf("planted name committed or echoed: %v %s", err, out)
	}
	git("reset", "-q")
	if out, err := commit("clean.txt", "hostname dev1\n"); err != nil {
		t.Fatalf("clean commit refused: %s", out)
	}
}
