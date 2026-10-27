package tools

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lcleveland/network-mcp/internal/change/hash"
	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

const stale = "network-mcp-0123456789abcdef0123456789abcdef"

// startNexus is startChange for a stateful fake NX-OS dev1 whose mgmt0
// owns the connect address.
func startNexus(t *testing.T, su setup) (*env, *sshfake.Nexus) {
	t.Helper()
	dev := &sshfake.Nexus{}
	su.eng = &sshfake.Engine{Hostname: "dev1", Profile: sshfake.NXOS, Device: dev, Commands: map[string]string{"terminal width 511": "", "terminal length 0": ""}}
	if su.opt == (sshfake.Options{}) {
		su.opt = sshfake.Options{FailUser: "mcp"}
	}
	su.platform, su.allowConfig, su.rules = "cisco_nxos", true, []config.Rule{writeRule}
	e := startWith(t, su)
	dev.Running = string(must(os.ReadFile(napalm+"nxos_ssh_show_running_config.txt"))) +
		"interface mgmt0\n  vrf member management\n  ip address " + e.fake.Host + "/8\n"
	dev.Startup = dev.Running
	return e, dev
}

func sent(dev *sshfake.Nexus, suffix string) bool {
	return slices.ContainsFunc(dev.Log(), func(l string) bool { return strings.HasSuffix(l, suffix) })
}

func TestNexusApplyConfirmSave(t *testing.T) {
	// sessions: 1 plan, 2 apply, 3 plan, 4 confirm
	e, dev := startNexus(t, setup{allowSave: true})
	out := applied(t, e)
	id := out["change_id"].(string)
	cp := "network-mcp-" + id
	if !slices.Equal(dev.Checkpoints(), []string{cp}) || out["post_hash"] != hash.Sum(dev.Config()) ||
		!strings.Contains(out["diff"].(string), "vlan 10") || fmt.Sprint(out["_untrusted"]) != "[diff]" ||
		out["warning"] != fmt.Sprintf("NX-OS revert is server-driven. If the server stops before the deadline, or this change cuts the server "+
			"off from the device, the change stays applied until an operator runs `rollback running-config checkpoint %s`.", cp) {
		t.Fatalf("apply: %v %q", out, dev.Checkpoints())
	}
	want := []string{"2 checkpoint " + cp, "2 configure terminal", "2 vlan 10", "2 name users", "2 end", "2 show diff rollback-patch checkpoint " + cp + " running-config"}
	if log := dev.Log(); !slices.Equal(log[len(log)-len(want)-1:len(log)-1], want) { // then the post-hash read
		t.Fatalf("apply session: %q", log)
	}
	if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": planned(t, e), "reason": "r"}); !strings.Contains(errText, "in progress") {
		t.Fatalf("second apply: %s", errText)
	}

	out, errText := e.call(t, "network_change", act("confirm", id))
	if errText != "" || out["outcome"] != "confirmed" || len(dev.Checkpoints()) != 0 || !sent(dev, "no checkpoint "+cp) || sent(dev, "2 no checkpoint "+cp) {
		t.Fatalf("confirm: %v %s %q", out, errText, dev.Log())
	}
	a := e.audit.String()
	for _, w := range []string{`"event":"apply","outcome":"started"`, `"event":"apply","outcome":"ok"`, `"event":"confirm","outcome":"started"`,
		`"event":"confirm","outcome":"ok"`, `"platform":"nxos"`, `"via":"new_session"`} {
		if !strings.Contains(a, w) {
			t.Errorf("audit lacks %s", w)
		}
	}

	out, errText = e.call(t, "network_change", map[string]any{"action": "save", "device": "dev1", "reason": "keep it"})
	if errText != "" || out["outcome"] != "saved" || dev.Startup != dev.Config() {
		t.Fatalf("save: %v %s", out, errText)
	}
	dev.Checkpoint(stale) // another process's unconfirmed change
	if _, errText := e.call(t, "network_change", map[string]any{"action": "save", "device": "dev1", "reason": "r"}); !strings.Contains(errText, "pending on the device") {
		t.Fatalf("save beside a stale checkpoint: %s", errText)
	}
}

func TestNexusStaleCheckpoint(t *testing.T) {
	e, dev := startNexus(t, setup{opt: sshfake.Options{FailUser: "nobody"}}) // network_status reads
	dev.Checkpoint(stale)
	id := planned(t, e)
	if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": id, "reason": "r"}); !strings.Contains(errText, stale) {
		t.Fatalf("apply beside a stale checkpoint: %s", errText)
	}
	if sent(dev, "configure terminal") || len(dev.Checkpoints()) != 1 || !strings.Contains(e.audit.String(), `"event":"apply","outcome":"refused"`) {
		t.Fatalf("refused apply touched the device: %q", dev.Log())
	}
	st, _ := e.call(t, "network_status", map[string]any{"device": "dev1"})
	if fmt.Sprint(st["stale_checkpoints"]) != "["+stale+"]" || !strings.Contains(fmt.Sprint(st["_untrusted"]), "stale_checkpoints") ||
		!strings.Contains(fmt.Sprint(st["checks"]), "map[detail:network-mcp-* checkpoints mark") {
		t.Fatalf("network_status: %v", st)
	}

	// status with a change_id lists the device's other checkpoints
	e2, dev2 := startNexus(t, setup{})
	cid := applied(t, e2)["change_id"].(string)
	dev2.Checkpoint(stale)
	st, errText := e2.call(t, "network_change", map[string]any{"action": "status", "change_id": cid})
	if errText != "" || fmt.Sprint(st["stale_checkpoints"]) != "["+stale+"]" || len(st["pending"].([]any)) != 1 {
		t.Fatalf("status: %v %s", st, errText)
	}
}

func TestNexusApplyDeviceError(t *testing.T) {
	e, dev := startNexus(t, setup{})
	pre := dev.Running
	dev.Errors = map[string]string{"name users": "ERROR: VLAN name is invalid\n"}
	out, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": planned(t, e), "reason": "r"})
	if errText != "" || out["outcome"] != "device_error" || !strings.Contains(fmt.Sprint(out["device_error"]), "VLAN name") {
		t.Fatalf("%v %s", out, errText)
	}
	if !slices.ContainsFunc(dev.Log(), func(l string) bool { return strings.HasSuffix(l, " atomic") }) || dev.Config() != pre || len(dev.Checkpoints()) != 0 {
		t.Fatalf("not rolled back: %q %q", dev.Log(), dev.Checkpoints())
	}
	if a := e.audit.String(); !strings.Contains(a, `"event":"apply","outcome":"device_error"`) || !strings.Contains(a, `"post_hash":"`+hash.Sum(pre)) {
		t.Fatalf("audit: %s", a)
	}
}

func TestNexusConfirmDrift(t *testing.T) {
	e, dev := startNexus(t, setup{})
	id := applied(t, e)["change_id"].(string)
	dev.Running += "vlan 99\n"
	if _, errText := e.call(t, "network_change", act("confirm", id)); !strings.Contains(errText, "changed since apply") || len(dev.Checkpoints()) != 1 {
		t.Fatalf("confirm after drift: %s", errText)
	}
}

func TestNexusRollback(t *testing.T) {
	e, dev := startNexus(t, setup{})
	pre := dev.Running
	id := applied(t, e)["change_id"].(string)
	out, errText := e.call(t, "network_change", act("rollback", id))
	if errText != "" || out["outcome"] != "rolled_back" || dev.Config() != pre || len(dev.Checkpoints()) != 0 ||
		!strings.Contains(e.audit.String(), `"event":"rollback","outcome":"ok"`) {
		t.Fatalf("rollback: %v %s %q", out, errText, dev.Checkpoints())
	}

	// a failed rollback keeps the checkpoint and the change
	id = applied(t, e)["change_id"].(string)
	dev.RollbackReply = "ERROR: Rollback failed\n"
	out, errText = e.call(t, "network_change", act("rollback", id))
	if errText != "" || out["outcome"] != "device_error" || len(dev.Checkpoints()) != 1 {
		t.Fatalf("failed rollback: %v %s", out, errText)
	}
	if st, _ := e.call(t, "network_change", map[string]any{"action": "status"}); st["pending"] == nil {
		t.Fatal("a failed rollback freed the change")
	}
}

func TestNexusDeadline(t *testing.T) {
	for name, tc := range map[string]struct {
		setup   func(*sshfake.Nexus)
		outcome string
		kept    bool // the checkpoint stays as the marker
	}{
		"reverted":         {func(*sshfake.Nexus) {}, "reverted", false},
		"rollback refused": {func(d *sshfake.Nexus) { d.RollbackReply = "ERROR: Rollback failed\n" }, "not_reverted", true},
		"hash mismatch":    {func(d *sshfake.Nexus) { d.RollbackReply = "Rollback completed successfully.\n" }, "not_reverted", true},
		"unreachable":      {func(d *sshfake.Nexus) { d.Down = true }, "unreachable", true},
	} {
		t.Run(name, func(t *testing.T) {
			e, dev := startNexus(t, setup{})
			advance := clock(e)
			pre := dev.Running
			applied(t, e)
			tc.setup(dev)
			advance(5*time.Minute - time.Second)
			e.deps.sweep()
			if strings.Contains(e.audit.String(), `"event":"deadline"`) {
				t.Fatal("rolled back before the deadline")
			}
			advance(time.Second) // no grace: the server reverts at the deadline
			e.deps.sweep()
			if a := e.audit.String(); !strings.Contains(a, `"event":"deadline","outcome":"`+tc.outcome+`"`) {
				t.Fatalf("audit: %s", a)
			}
			if kept := len(dev.Checkpoints()) == 1; kept != tc.kept || !kept && dev.Config() != pre {
				t.Fatalf("checkpoints %q", dev.Checkpoints())
			}
			if st, _ := e.call(t, "network_change", map[string]any{"action": "status"}); st["pending"] != nil {
				t.Fatalf("the deadline did not free the slot: %v", st)
			}
		})
	}
}

func TestNexusDenied(t *testing.T) {
	e, dev := startNexus(t, setup{})
	for _, l := range []string{"checkpoint x", "rollback running-config checkpoint x", "feature bgp", "no feature telnet"} {
		if _, errText := e.call(t, "network_change", plan(l)); errText == "" {
			t.Errorf("%q planned", l)
		}
	}
	if len(dev.Log()) != 0 {
		t.Fatalf("a denied plan reached the device: %q", dev.Log())
	}
}

func TestNexusAuditFailClosed(t *testing.T) {
	w := &flaky{}
	e, dev := startNexus(t, setup{auditW: w})
	id := planned(t, e)
	w.fail.Store(true)
	if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": id, "reason": "r"}); !strings.Contains(errText, "audit") {
		t.Fatalf("apply: %q", errText)
	}
	if sent(dev, "configure terminal") || len(dev.Checkpoints()) != 0 {
		t.Fatalf("apply reached the device: %q", dev.Log())
	}
	w.fail.Store(false)
	cid := applied(t, e)["change_id"].(string)
	w.fail.Store(true)
	for _, a := range []string{"confirm", "rollback"} {
		if _, errText := e.call(t, "network_change", act(a, cid)); !strings.Contains(errText, "audit") || len(dev.Checkpoints()) != 1 {
			t.Fatalf("%s: %q", a, errText)
		}
	}
	if sent(dev, "no checkpoint network-mcp-"+cid) || sent(dev, " atomic") {
		t.Fatalf("a step without its audit line reached the device: %q", dev.Log())
	}
}
