package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/output"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshcli"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

// fakeSecrets were dropped from the fixtures by cmd/sanitize, so the tests
// put obvious fakes back. Each line holds exactly one secret.
const fakeSecrets = "enable secret 9 $9$fakehash\nusername user1 privilege 15 secret 9 $9$fakehash\n" +
	"snmp-server community fakecomm RO\ntacacs-server host 192.0.2.50 key 0 fakekey\n"

func TestConfig(t *testing.T) {
	for _, tc := range []struct {
		platform, file string
		profile        sshfake.Profile
	}{
		{"cisco_iosxe", napalm + "ios_show_running_config.txt", sshfake.IOSXE},
		{"nxos", napalm + "nxos_ssh_show_running_config.txt", sshfake.NXOS},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			run := string(must(os.ReadFile(tc.file))) + fakeSecrets
			start := "!Startup config\n" + fakeSecrets
			e := startWith(t, setup{platform: tc.platform, eng: &sshfake.Engine{Hostname: "dev1", Profile: tc.profile, Commands: map[string]string{
				"terminal width 512": "", "terminal width 511": "", "terminal length 0": "",
				"show running-config": run, "show startup-config": start,
			}}})
			_, base, _ := (*output.Filter)(nil).Text(string(must(os.ReadFile(tc.file))), false)
			out, errText := e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "running"})
			got := fmt.Sprint(out["output"])
			if errText != "" || out["device"] != "dev1" || out["source"] != "running" || fmt.Sprint(out["_untrusted"]) != "[output]" ||
				out["_redactions"] != float64(base+4) || strings.Count(got, output.Redacted) != base+4 || strings.Contains(got, "fake") ||
				!strings.Contains(got, "enable secret 9 <redacted>") || !strings.Contains(got, "\nversion fw1\n") || len(out) != 5 {
				t.Fatalf("running: %.300v %s", out, errText)
			}

			out, _ = e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "startup"})
			if !strings.HasPrefix(fmt.Sprint(out["output"]), "!Startup config\nenable secret 9 <redacted>\n") || out["_redactions"] != 4.0 {
				t.Fatalf("startup: %v", out)
			}

			out, _ = e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "running",
				"section": "^interface ", "include": []string{"^interface |ip address"}})
			got = fmt.Sprint(out["output"])
			if !strings.HasPrefix(got, "interface ") || !strings.Contains(got, "ip address 192.0.2.") || strings.Contains(got, "shutdown") || strings.Contains(got, "router") {
				t.Fatalf("section/include: %v", out)
			}

			var sent []string
			for _, c := range e.commands() {
				if strings.HasPrefix(c, "show") {
					sent = append(sent, c)
				}
			}
			if !slices.Equal(sent, []string{"show running-config", "show startup-config", "show running-config"}) {
				t.Errorf("sent %q", sent)
			}
		})
	}
}

func TestConfigBig(t *testing.T) {
	// the NX-OS fixture's 144 interfaces, padded past 60 KiB, then a BGP block
	var big strings.Builder
	big.Write(must(os.ReadFile(napalm + "nxos_ssh_show_running_config.txt")))
	for i := range 1000 {
		fmt.Fprintf(&big, "interface Ethernet9/%d\n  description pad\n", i)
	}
	big.WriteString("router bgp 64496\n  neighbor 192.0.2.2\n    password 3 fakebgp\n")
	e := startWith(t, setup{platform: "nxos", eng: &sshfake.Engine{Hostname: "dev1", Profile: sshfake.NXOS, Commands: map[string]string{
		"terminal width 511": "", "terminal length 0": "", "show running-config": big.String(),
		"show startup-config": strings.Repeat(strings.Repeat("z", 1023)+"\n", sshcli.MaxRead>>10+1),
	}}})

	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "network_config", Arguments: map[string]any{"action": "get", "device": "dev1", "source": "running"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	json.Unmarshal(b, &out)
	if tr, _ := out["_truncation"].(map[string]any); len(b) > output.MaxResult || tr["reason"] != "bytes" || tr["hint"] != output.HintCLI {
		t.Fatalf("%d bytes, %v", len(b), out["_truncation"])
	}
	out, _ = e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "running", "section": "^router bgp 64496"})
	if out["output"] != "router bgp 64496\n  neighbor 192.0.2.2\n    password 3 <redacted>" || out["_truncation"] != nil {
		t.Fatalf("section past 60 KiB: %v", out)
	}

	// unredacted for export and hashing; whole or not at all
	ctx := context.Background()
	if s, err := e.deps.FetchConfig(ctx, "dev1", "running", ""); err != nil || !strings.HasSuffix(s, "password 3 fakebgp") {
		t.Fatalf("FetchConfig: %.100q %v", s, err)
	}
	if s, err := e.deps.FetchConfig(ctx, "dev1", "startup", ""); s != "" || err == nil {
		t.Fatalf("FetchConfig over 16 MiB: %d bytes, %v", len(s), err)
	}
	out, _ = e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "startup"})
	if !strings.Contains(fmt.Sprint(out["device_error"]), "exceeds") || out["output"] != nil {
		t.Fatalf("over 16 MiB: %.300v", out)
	}
}

func TestConfigPlatforms(t *testing.T) {
	cmds := map[string]string{"show config running": "hostname dev1\nsnmp community fakecomm"}
	e := startWith(t, setup{platform: "aos", eng: &sshfake.Engine{Hostname: "dev1", Commands: cmds}})
	if _, errText := e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "running"}); !strings.Contains(errText, "platforms.aos.config.running") {
		t.Fatalf("unset platform config: %s", errText)
	}
	for _, args := range []map[string]any{{"source": "candidate"}, {"source": "running", "action": "set"}, {"source": "running", "include": []string{"("}}} {
		args["device"] = "dev1"
		if args["action"] == nil {
			args["action"] = "get"
		}
		if _, errText := e.call(t, "network_config", args); errText == "" {
			t.Errorf("%v accepted", args)
		}
	}
	// network_show still refuses config dumps; only network_config may send them
	for _, c := range []string{"show running-config", "show startup-config", "show run"} {
		if _, errText := e.call(t, "network_show", map[string]any{"device": "dev1", "command": c}); !strings.Contains(errText, "denied") {
			t.Errorf("network_show %q: %s", c, errText)
		}
	}
	if got := e.commands(); len(got) != 0 {
		t.Fatalf("sent %q", got)
	}

	e = startWith(t, setup{platform: "aos", eng: &sshfake.Engine{Hostname: "dev1", Commands: cmds},
		platforms: map[string]platform.Config{"AOS": {Config: platform.ConfigCmds{Running: "show config running"}}}})
	out, _ := e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "running"})
	if out["output"] != "hostname dev1\nsnmp community <redacted>" || out["_redactions"] != 1.0 {
		t.Fatalf("configured command: %v", out)
	}
	if got := e.commands(); !slices.Equal(got, []string{"show config running"}) {
		t.Fatalf("sent %q", got)
	}
	if _, errText := e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "startup"}); !strings.Contains(errText, "platforms.aos.config.startup") {
		t.Fatalf("unset startup: %s", errText)
	}

	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Name == "network_config" && (!tl.Annotations.ReadOnlyHint || !*tl.Annotations.OpenWorldHint) {
			t.Errorf("annotations: %+v", tl.Annotations)
		}
	}
}
