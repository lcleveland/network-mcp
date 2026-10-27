package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/sshcli"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

// startExport serves IOS-XE dev1 with a dir destination "local" at the
// returned root.
func startExport(t *testing.T, redact *bool, startup string, groups ...string) (*env, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "export")
	e := startWith(t, setup{platform: "cisco_iosxe", groups: groups,
		dests: map[string]config.Destination{"local": {Type: "dir", Path: root, Redact: redact}},
		eng: &sshfake.Engine{Hostname: "dev1", Profile: sshfake.IOSXE, Commands: map[string]string{
			"terminal width 512": "", "terminal length 0": "",
			"show running-config": "hostname dev1\n" + fakeSecrets, "show startup-config": startup,
		}}})
	return e, root
}

func exportArgs(devices ...any) map[string]any {
	return map[string]any{"devices": devices, "kinds": []string{"running", "startup"}, "destination": "local", "reason": "test backup"}
}

func results(out map[string]any) []map[string]any {
	var rs []map[string]any
	b, _ := json.Marshal(out["results"])
	json.Unmarshal(b, &rs)
	return rs
}

func TestExport(t *testing.T) {
	e, root := startExport(t, nil, "!startup\n")
	out, errText := e.call(t, "network_export", exportArgs("dev1", "dev-outside"))
	rs := results(out)
	if errText != "" || len(rs) != 4 {
		t.Fatalf("%v %s", out, errText)
	}
	for _, r := range rs[:2] {
		file := filepath.Join(root, fmt.Sprint(r["ref"]))
		b := must(os.ReadFile(file))
		h := sha256.Sum256(b)
		if r["changed"] != true || r["destination"] != "local" || r["sha256"] != hex.EncodeToString(h[:]) || r["ref"] != "dev1/"+fmt.Sprint(r["kind"])+".txt" {
			t.Fatalf("first export: %v", r)
		}
		if strings.Contains(string(b), "fake") {
			t.Fatalf("unredacted file: %s", b)
		}
	}
	if got := string(must(os.ReadFile(filepath.Join(root, "dev1/running.txt")))); !strings.Contains(got, "enable secret 9 "+output.Redacted) {
		t.Fatalf("running.txt: %s", got)
	}
	if !strings.Contains(fmt.Sprint(rs[2]["error"]), "outside") || rs[2]["ref"] != nil || len(must(os.ReadDir(root))) != 1 {
		t.Fatalf("refused device: %v", rs[2])
	}
	if b, _ := json.Marshal(out); strings.Contains(string(b), "hostname") {
		t.Fatalf("config text in result: %s", b)
	}
	a := e.audit.String()
	if !strings.Contains(a, `"event":"export"`) || !strings.Contains(a, `"reason":"test backup"`) || !strings.Contains(a, `"redact":true`) ||
		!strings.Contains(a, `"refs":["dev1/running.txt","dev1/startup.txt"]`) || !strings.Contains(a, fmt.Sprint(rs[0]["sha256"])) || strings.Contains(a, "fake") {
		t.Fatalf("audit: %s", a)
	}

	st := must(os.Stat(filepath.Join(root, "dev1/running.txt")))
	out, _ = e.call(t, "network_export", exportArgs("dev1"))
	if rs := results(out); rs[0]["changed"] != false || rs[1]["changed"] != false || rs[0]["ref"] != "dev1/running.txt" {
		t.Fatalf("second export: %v", out)
	}
	if !must(os.Stat(filepath.Join(root, "dev1/running.txt"))).ModTime().Equal(st.ModTime()) {
		t.Fatal("identical export rewrote the file")
	}
	if strings.Contains(e.log.String(), "unredacted") {
		t.Fatal("redacted export logged as unredacted")
	}
}

func TestExportUnredacted(t *testing.T) {
	e, root := startExport(t, new(false), "!startup\n")
	for range 2 {
		if _, errText := e.call(t, "network_export", exportArgs("dev1")); errText != "" {
			t.Fatal(errText)
		}
	}
	if got := string(must(os.ReadFile(filepath.Join(root, "dev1/running.txt")))); got != strings.TrimSuffix("hostname dev1\n"+fakeSecrets, "\n") {
		t.Fatalf("raw file: %q", got)
	}
	if n := strings.Count(e.log.String(), "exporting configs unredacted"); n != 2 || !strings.Contains(e.audit.String(), `"redact":false`) {
		t.Fatalf("%d warnings; audit %s", n, e.audit)
	}
}

func TestExportRefusals(t *testing.T) {
	e, root := startExport(t, nil, "!startup\n")
	many := make([]any, MaxExport+1)
	for i := range many {
		many[i] = "dev1"
	}
	cases := []map[string]any{
		{"devices": []string{"dev1"}, "kinds": []string{"running"}, "destination": "local"},
		{"devices": []string{"dev1"}, "kinds": []string{"running"}, "destination": "local", "reason": " "},
		exportArgs(many...),
		{"devices": []string{"dev1"}, "kinds": []string{"candidate"}, "destination": "local", "reason": "x"},
		{"devices": []string{"dev1"}, "kinds": []string{"running"}, "destination": "elsewhere", "reason": "x"},
	}
	for _, name := range []string{"a/b", "..", "x..y", ".hidden", "a\x01b", `a\b`, "127.0.0.1", "2001:db8::1", ""} {
		cases = append(cases, exportArgs(name))
	}
	for _, args := range cases {
		if _, errText := e.call(t, "network_export", args); errText == "" {
			t.Errorf("%v accepted", args)
		}
	}
	if got := e.commands(); len(got) != 0 {
		t.Fatalf("a refused export reached the device: %q", got)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused export wrote: %v", err)
	}

	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Name != "network_export" {
			continue
		}
		b, _ := json.Marshal(tl.InputSchema)
		if a := tl.Annotations; a.ReadOnlyHint || *a.DestructiveHint || !a.IdempotentHint || !*a.OpenWorldHint || strings.Contains(strings.ToLower(string(b)), "redact") {
			t.Errorf("annotations %+v, schema %s", a, b)
		}
	}
}

func TestExportAbsent(t *testing.T) {
	for _, e := range []*env{start(t, nil, sshfake.Options{}), must2(startExport(t, nil, "", "core", "cli"))} {
		res, err := e.cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tl := range res.Tools {
			if tl.Name == "network_export" {
				t.Fatal("network_export listed")
			}
		}
	}
}

func TestExportBig(t *testing.T) {
	e, root := startExport(t, nil, strings.Repeat(strings.Repeat("z", 1023)+"\n", sshcli.MaxRead>>10+1))
	out, _ := e.call(t, "network_export", exportArgs("dev1"))
	if rs := results(out); !strings.Contains(fmt.Sprint(rs[0]["error"]), "exceeds") || rs[0]["ref"] != nil || rs[1]["ref"] != nil {
		t.Fatalf("over 16 MiB: %v", out)
	}
	if _, err := os.Stat(filepath.Join(root, "dev1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("part of an oversized device was written: %v", err)
	}
}

func TestExportAuditFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "export")
	e := startWith(t, setup{auditW: failWriter{}, dests: map[string]config.Destination{"local": {Type: "dir", Path: root}}, platform: "cisco_iosxe",
		eng: &sshfake.Engine{Hostname: "dev1", Profile: sshfake.IOSXE, Commands: map[string]string{
			"terminal width 512": "", "terminal length 0": "", "show running-config": "hostname dev1"}}})
	if _, errText := e.call(t, "network_export", map[string]any{"devices": []string{"dev1"}, "kinds": []string{"running"}, "destination": "local", "reason": "x"}); !strings.Contains(errText, "audit") {
		t.Fatalf("export without audit: %s", errText)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("written without an audit line: %v", err)
	}
}

func TestExportPushFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo")
	e := startWith(t, setup{platform: "cisco_iosxe",
		dests: map[string]config.Destination{"local": {Type: "git", Path: path, Branch: "main", Remote: "https://127.0.0.1:1/r.git", Credential: "push"}},
		eng: &sshfake.Engine{Hostname: "dev1", Profile: sshfake.IOSXE, Commands: map[string]string{
			"terminal width 512": "", "terminal length 0": "", "show running-config": "hostname dev1", "show startup-config": "hostname dev1"}}})
	out, errText := e.call(t, "network_export", exportArgs("dev1"))
	rs := results(out)
	if errText != "" || len(rs) != 2 || rs[0]["changed"] != true || len(fmt.Sprint(rs[0]["ref"])) != 40 || !strings.Contains(fmt.Sprint(rs[0]["error"]), "push failed") {
		t.Fatalf("%v %s", out, errText)
	}
	if !strings.Contains(e.audit.String(), `"outcome":"error"`) {
		t.Fatalf("audit: %s", e.audit)
	}
}

func must2[A, B any](a A, _ B) A { return a }
