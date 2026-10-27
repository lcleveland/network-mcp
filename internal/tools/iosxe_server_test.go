package tools

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/platform"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

// startNoArchive is startChange for an IOS-XE dev1 without archive path,
// on a platform set to revert: server.
func startNoArchive(t *testing.T, su setup) (*env, *sshfake.Device) {
	t.Helper()
	su.allowConfig, su.rules = true, []config.Rule{writeRule}
	su.platforms = map[string]platform.Config{"cisco_iosxe": {Revert: platform.RevertServer}}
	e, dev := startChange(t, su)
	dev.Running = strings.Replace(dev.Running, "archive\n path flash:archive\n", "", 1)
	dev.Startup = dev.Running
	return e, dev
}

func logged(dev *sshfake.Device, suffix string) bool {
	return slices.ContainsFunc(dev.Log(), func(l string) bool { return strings.HasSuffix(l, suffix) })
}

func TestNoArchiveNeedsServerRevert(t *testing.T) {
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	dev.Running = strings.Replace(dev.Running, "archive\n path flash:archive\n", "", 1)
	_, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": planned(t, e), "reason": "r"})
	if !strings.Contains(errText, "archive path is not configured") || !strings.Contains(errText, "revert: server") || configMode(dev) {
		t.Fatalf("apply without archive: %s", errText)
	}
}

func TestServerRevertApplyConfirm(t *testing.T) {
	e, dev := startNoArchive(t, setup{})
	out := applied(t, e)
	id := out["change_id"].(string)
	snap := "network-mcp-" + id + ".cfg"
	if !slices.Equal(dev.Files(), []string{snap}) || !strings.Contains(dev.Config(), "vlan 10") ||
		!strings.Contains(out["diff"].(string), "vlan 10") || !strings.Contains(fmt.Sprint(out["warning"]), "configure replace flash:"+snap+" force") {
		t.Fatalf("apply: %v %q", out, dev.Files())
	}
	want := []string{"copy running-config flash:" + snap, "configure terminal", "vlan 10", "name users", "end",
		"show archive config differences flash:" + snap + " system:running-config"}
	for _, w := range want {
		if !logged(dev, " "+w) {
			t.Fatalf("apply never sent %q: %q", w, dev.Log())
		}
	}
	if logged(dev, "revert timer 5") || logged(dev, "show archive config rollback timer") {
		t.Fatalf("server revert used the archive: %q", dev.Log())
	}
	out, errText := e.call(t, "network_change", act("confirm", id))
	if errText != "" || out["outcome"] != "confirmed" || len(dev.Files()) != 0 || !strings.Contains(dev.Config(), "vlan 10") {
		t.Fatalf("confirm: %v %s %q", out, errText, dev.Files())
	}
}

func TestServerRevertRollbackAndError(t *testing.T) {
	e, dev := startNoArchive(t, setup{})
	pre := dev.Running
	id := applied(t, e)["change_id"].(string)
	out, errText := e.call(t, "network_change", act("rollback", id))
	if errText != "" || out["outcome"] != "rolled_back" || dev.Config() != pre || len(dev.Files()) != 0 {
		t.Fatalf("rollback: %v %s %q", out, errText, dev.Files())
	}

	e, dev = startNoArchive(t, setup{})
	pre = dev.Running
	dev.Errors = map[string]string{"name users": "% Invalid input detected at '^' marker.\n"}
	out, errText = e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": planned(t, e), "reason": "r"})
	if errText != "" || out["outcome"] != "device_error" || dev.Config() != pre || len(dev.Files()) != 0 || !logged(dev, "force") {
		t.Fatalf("device error: %v %s %q", out, errText, dev.Files())
	}
}

func TestServerRevertDeadline(t *testing.T) {
	e, dev := startNoArchive(t, setup{})
	advance := clock(e)
	pre := dev.Running
	applied(t, e)
	advance(5 * time.Minute) // no grace: the server reverts at the deadline
	e.deps.sweep()
	if a := e.audit.String(); !strings.Contains(a, `"event":"deadline","outcome":"reverted"`) || dev.Config() != pre || len(dev.Files()) != 0 {
		t.Fatalf("deadline: %q %s", dev.Files(), a)
	}
}

func TestServerRevertLeftoverSnapshot(t *testing.T) {
	e, dev := startNoArchive(t, setup{opt: sshfake.Options{FailUser: "nobody"}})
	left := "network-mcp-0123456789abcdef.cfg"
	dev.Put(left, dev.Running)
	if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": planned(t, e), "reason": "r"}); !strings.Contains(errText, left) || configMode(dev) {
		t.Fatalf("apply beside a leftover snapshot: %s", errText)
	}
	st, _ := e.call(t, "network_status", map[string]any{"device": "dev1"})
	if fmt.Sprint(st["stale_checkpoints"]) != "["+left+"]" {
		t.Fatalf("network_status: %v", st)
	}
}
