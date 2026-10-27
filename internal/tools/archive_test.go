package tools

import (
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/platform"
)

func TestArchiveAction(t *testing.T) {
	arch := map[string]any{"action": "archive", "device": "dev1", "reason": "let changes use the revert timer"}

	// without archive_path the server never touches archive
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	dev.Running = strings.Replace(dev.Running, "archive\n path flash:archive\n", "", 1)
	if _, errText := e.call(t, "network_change", arch); !strings.Contains(errText, "sets no archive_path") || configMode(dev) {
		t.Fatalf("no archive_path: %s %q", errText, dev.Log())
	}

	e, dev = startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule},
		platforms: map[string]platform.Config{"cisco_iosxe": {ArchivePath: "flash:mcp-archive"}}})
	dev.Running = strings.Replace(dev.Running, "archive\n path flash:archive\n", "", 1)
	dev.Locked = true
	if out, _ := e.call(t, "network_change", arch); out["outcome"] != "device_error" || !strings.Contains(dev.Config(), "interface") || strings.Contains(dev.Config(), "mcp-archive") {
		t.Fatalf("locked: %v", out)
	}
	dev.Locked = false
	out, errText := e.call(t, "network_change", arch)
	if errText != "" || out["outcome"] != "archive_configured" || !strings.Contains(dev.Config(), "archive\n path flash:mcp-archive\n") || out["post_hash"] == out["pre_hash"] {
		t.Fatalf("archive: %v %s", out, errText)
	}
	if a := e.audit.String(); !strings.Contains(a, `"event":"archive","outcome":"started"`) || !strings.Contains(a, `"event":"archive","outcome":"ok"`) {
		t.Fatalf("audit: %s", a)
	}
	// the device's own revert timer works now
	id := applied(t, e)["change_id"].(string)
	if !dev.Pending() {
		t.Fatal("apply after archive did not start the revert timer")
	}
	if _, errText := e.call(t, "network_change", arch); !strings.Contains(errText, "in progress") {
		t.Fatalf("archive beside a pending change: %s", errText)
	}
	if _, errText := e.call(t, "network_change", act("confirm", id)); errText != "" {
		t.Fatal(errText)
	}

	before := len(dev.Log())
	if out, _ := e.call(t, "network_change", arch); out["outcome"] != "already_configured" || strings.Contains(strings.Join(dev.Log()[before:], ";"), "configure terminal") {
		t.Fatalf("second archive: %v", out)
	}
}

func TestArchiveThenSave(t *testing.T) {
	su := setup{allowConfig: true, allowSave: true, rules: []config.Rule{writeRule},
		platforms: map[string]platform.Config{"cisco_iosxe": {ArchivePath: "flash:mcp-archive"}}}
	save := map[string]any{"action": "save", "device": "dev1", "reason": "keep the archive block"}
	arch := map[string]any{"action": "archive", "device": "dev1", "reason": "r"}

	// already configured: nothing this server made, so nothing to save
	e, _ := startChange(t, su)
	if out, _ := e.call(t, "network_change", arch); out["outcome"] != "already_configured" {
		t.Fatalf("archive: %v", out)
	}
	if _, errText := e.call(t, "network_change", save); !strings.Contains(errText, "no change confirmed") {
		t.Fatalf("save after already_configured: %s", errText)
	}

	e, dev := startChange(t, su)
	dev.Running = strings.Replace(dev.Running, "archive\n path flash:archive\n", "", 1)
	if out, _ := e.call(t, "network_change", arch); out["outcome"] != "archive_configured" {
		t.Fatalf("archive: %v", out)
	}
	out, errText := e.call(t, "network_change", save)
	if errText != "" || out["outcome"] != "saved" || dev.Startup != dev.Config() || !strings.Contains(dev.Startup, "path flash:mcp-archive") {
		t.Fatalf("save after archive: %v %s", out, errText)
	}

	// someone else's edit after archive is never saved
	e, dev = startChange(t, su)
	dev.Running = strings.Replace(dev.Running, "archive\n path flash:archive\n", "", 1)
	e.call(t, "network_change", arch)
	dev.Running += "vlan 99\n"
	if _, errText := e.call(t, "network_change", save); !strings.Contains(errText, "differs from the last change") {
		t.Fatalf("save after drift: %s", errText)
	}
}
