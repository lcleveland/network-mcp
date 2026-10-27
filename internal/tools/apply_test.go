package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/change/hash"
	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/sshcli"
	"github.com/lcleveland/network-mcp/internal/sshfake"
)

// clock fakes the store's clock and returns a function that advances it.
func clock(e *env) func(time.Duration) {
	now := time.Now()
	e.deps.Changes.Now = func() time.Time { return now }
	return func(d time.Duration) { now = now.Add(d) }
}

// planned plans the users VLAN and returns the plan_id.
func planned(t *testing.T, e *env) string {
	t.Helper()
	out, errText := e.call(t, "network_change", plan("vlan 10", "name users"))
	if errText != "" {
		t.Fatal(errText)
	}
	return out["plan_id"].(string)
}

func applied(t *testing.T, e *env, args ...any) map[string]any {
	t.Helper()
	in := map[string]any{"action": "apply", "plan_id": planned(t, e), "reason": "add the users VLAN"}
	for i := 0; i < len(args); i += 2 {
		in[args[i].(string)] = args[i+1]
	}
	out, errText := e.call(t, "network_change", in)
	if errText != "" || out["outcome"] != "applied" {
		t.Fatalf("apply: %v %s", out, errText)
	}
	return out
}

func act(action, changeID string) map[string]any {
	return map[string]any{"action": action, "change_id": changeID, "reason": "checked"}
}

// configMode reports whether any session entered config mode or reverted.
func configMode(dev *sshfake.Device) bool {
	return slices.ContainsFunc(dev.Log(), func(l string) bool {
		return strings.Contains(l, " configure terminal") || strings.Contains(l, " configure revert")
	})
}

func TestChangeApplyConfirmSave(t *testing.T) {
	// sessions: 1 plan, 2 apply, 3 the read below, 4 confirm
	e, dev := startChange(t, setup{allowConfig: true, allowSave: true, rules: []config.Rule{writeRule}, opt: sshfake.Options{FailUser: "nobody"}})
	pre := hash.Sum(dev.Running)
	out := applied(t, e)
	id := out["change_id"].(string)
	if len(id) != 32 || out["post_hash"] == pre || out["post_hash"] != hash.Sum(dev.Config()) || out["deadline"] == nil ||
		!strings.Contains(out["diff"].(string), "+vlan 10") || fmt.Sprint(out["_untrusted"]) != "[diff]" || !dev.Pending() {
		t.Fatalf("apply: %v", out)
	}
	st, _ := e.call(t, "network_change", map[string]any{"action": "status"})
	if fmt.Sprint(st["changes"]) != "map[max_pending_changes:1 pending_changes:1 pending_plans:0]" || len(st["pending"].([]any)) != 1 {
		t.Fatalf("status: %v", st)
	}
	// reads never wait for the slot
	if r, errText := e.call(t, "network_config", map[string]any{"action": "get", "device": "dev1", "source": "running"}); errText != "" || r["device_error"] != nil {
		t.Fatalf("read during a pending change: %v %s", r, errText)
	}

	out, errText := e.call(t, "network_change", act("confirm", id))
	if errText != "" || out["outcome"] != "confirmed" || dev.Pending() {
		t.Fatalf("confirm: %v %s", out, errText)
	}
	log := dev.Log()
	want := []string{"2 configure terminal revert timer 5", "2 vlan 10", "2 name users", "2 end", "2 show archive config differences"}
	if i := slices.Index(log, want[0]); i < 0 || !slices.Equal(log[i:i+len(want)], want) {
		t.Fatalf("apply session: %q", log)
	}
	if !slices.Contains(log, "4 configure confirm") || slices.ContainsFunc(log, func(l string) bool { return strings.HasSuffix(l, "configure confirm") && l[0] != '4' }) {
		t.Fatalf("confirm was not sent on a new session only: %q", log)
	}
	a := e.audit.String()
	for _, w := range []string{`"event":"apply","outcome":"started"`, `"event":"apply","outcome":"ok"`, `"event":"confirm","outcome":"ok"`,
		`"change_id":"` + id, `"revert_minutes":5`, `"deadline":"`, `"post_hash":"` + out["post_hash"].(string), `"via":"new_session"`} {
		if !strings.Contains(a, w) {
			t.Errorf("audit lacks %s", w)
		}
	}
	if _, errText := e.call(t, "network_change", act("confirm", id)); errText == "" {
		t.Fatal("a confirmed change confirmed twice")
	}

	out, errText = e.call(t, "network_change", map[string]any{"action": "save", "device": "dev1", "reason": "keep it"})
	if errText != "" || out["outcome"] != "saved" || dev.Startup != dev.Config() {
		t.Fatalf("save: %v %s", out, errText)
	}
	dev.Running += "hostname drifted\n"
	if _, errText := e.call(t, "network_change", map[string]any{"action": "save", "device": "dev1", "reason": "keep it"}); !strings.Contains(errText, "differs") {
		t.Fatalf("save after drift: %s", errText)
	}
}

func TestChangeApplyPreconditions(t *testing.T) {
	for name, tc := range map[string]struct {
		before, after func(*env, *sshfake.Device)
		want          string
	}{
		"no archive":    {before: func(_ *env, d *sshfake.Device) { d.Running = strings.Replace(d.Running, "archive\n", "", 1) }, want: "archive path"},
		"pending timer": {after: func(e *env, d *sshfake.Device) { startTimer(t, e) }, want: "revert timer"},
		"locked":        {after: func(_ *env, d *sshfake.Device) { d.Locked = true }, want: "locked"},
		"hash drift":    {after: func(_ *env, d *sshfake.Device) { d.Running += "vlan 99\n" }, want: "changed since the plan"},
	} {
		t.Run(name, func(t *testing.T) {
			e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
			if tc.before != nil {
				tc.before(e, dev)
			}
			id := planned(t, e)
			if tc.after != nil {
				tc.after(e, dev)
			}
			busy := dev.Pending()
			n := len(dev.Log())
			_, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": id, "reason": "r"})
			if !strings.Contains(errText, tc.want) {
				t.Fatalf("%q, want %q", errText, tc.want)
			}
			if !busy && configMode(dev) || busy && slices.ContainsFunc(dev.Log()[n:], func(l string) bool { return strings.Contains(l, "configure") }) {
				t.Fatalf("config mode entered: %q", dev.Log())
			}
			if !strings.Contains(e.audit.String(), `"event":"apply","outcome":"refused"`) {
				t.Fatalf("audit: %s", e.audit)
			}
			if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": id, "reason": "r"}); !strings.Contains(errText, "unknown") {
				t.Fatalf("a refused apply left the plan usable: %s", errText)
			}
		})
	}
}

// startTimer leaves a revert timer pending, as another process would.
func startTimer(t *testing.T, e *env) {
	t.Helper()
	c, _ := creds.Read(e.deps.Config.CredentialsDir, "ssh-write")
	s, err := sshcli.Open(context.Background(), sshcli.Target{Addr: netip.MustParseAddr(e.fake.Host), Port: e.fake.Port,
		KnownHosts: e.fake.KnownHosts, Cred: c, Timeout: 5 * time.Second, Driver: "iosxe"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, cmd := range []string{"configure terminal revert timer 10", "end"} {
		if _, err := s.Run(context.Background(), cmd); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChangeApplyDeviceError(t *testing.T) {
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	pre := dev.Running
	dev.Errors = map[string]string{"name users": "% Invalid input detected at '^' marker.\n"}
	id := planned(t, e)
	out, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": id, "reason": "r"})
	if errText != "" || out["outcome"] != "device_error" || !strings.Contains(fmt.Sprint(out["device_error"]), "Invalid input") ||
		fmt.Sprint(out["_untrusted"]) != "[device_error]" {
		t.Fatalf("%v %s", out, errText)
	}
	if !slices.ContainsFunc(dev.Log(), func(l string) bool { return strings.HasSuffix(l, " configure revert now") }) || dev.Config() != pre || dev.Pending() {
		t.Fatalf("not reverted: %q", dev.Log())
	}
	if a := e.audit.String(); !strings.Contains(a, `"event":"apply","outcome":"device_error"`) || !strings.Contains(a, `"post_hash":"`+hash.Sum(pre)) {
		t.Fatalf("audit: %s", a)
	}
	if st, _ := e.call(t, "network_change", map[string]any{"action": "status"}); st["pending"] != nil {
		t.Fatalf("a failed apply holds the slot: %v", st)
	}
}

func TestChangeConfirmRefusals(t *testing.T) {
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	advance := clock(e)
	pre := hash.Sum(dev.Running)
	id := applied(t, e)["change_id"].(string)
	dev.Running += "vlan 99\n"
	if _, errText := e.call(t, "network_change", act("confirm", id)); !strings.Contains(errText, "changed since apply") || !dev.Pending() {
		t.Fatalf("confirm after drift: %s", errText)
	}
	// the device timer fires; the deadline check sees pre_hash
	dev.Expire()
	advance(5*time.Minute + deadlineGrace)
	if _, errText := e.call(t, "network_change", act("confirm", id)); !strings.Contains(errText, "deadline") {
		t.Fatalf("confirm after the deadline: %s", errText)
	}
	e.deps.sweep()
	if a := e.audit.String(); !strings.Contains(a, `"event":"deadline","outcome":"reverted"`) || !strings.Contains(a, `"running_hash":"`+pre) {
		t.Fatalf("audit: %s", a)
	}
	if st, _ := e.call(t, "network_change", map[string]any{"action": "status"}); st["pending"] != nil {
		t.Fatalf("the deadline did not free the slot: %v", st)
	}
	if _, errText := e.call(t, "network_change", act("rollback", id)); !strings.Contains(errText, "unknown") {
		t.Fatalf("rollback of an expired change: %s", errText)
	}
}

func TestChangeConfirmFallback(t *testing.T) {
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	dev.SessionBound = true // sessions: 1 plan, 2 apply, 3 confirm
	id := applied(t, e)["change_id"].(string)
	if out, errText := e.call(t, "network_change", act("confirm", id)); errText != "" || out["outcome"] != "confirmed" || dev.Pending() {
		t.Fatalf("%v %s", out, errText)
	}
	if log := dev.Log(); !slices.Contains(log, "3 configure confirm") || !slices.Contains(log, "2 configure confirm") ||
		!strings.Contains(e.audit.String(), `"via":"apply_session"`) {
		t.Fatalf("no fallback to the apply session: %q", log)
	}
}

func TestChangeRollbackAndDeadline(t *testing.T) {
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	advance := clock(e)
	pre := dev.Running
	id := applied(t, e)["change_id"].(string)
	out, errText := e.call(t, "network_change", act("rollback", id))
	if errText != "" || out["outcome"] != "rolled_back" || dev.Config() != pre || dev.Pending() {
		t.Fatalf("rollback: %v %s", out, errText)
	}
	if !strings.Contains(e.audit.String(), `"event":"rollback","outcome":"ok"`) {
		t.Fatalf("audit: %s", e.audit)
	}

	// not reverted: the timer never fired
	applied(t, e)
	advance(5 * time.Minute)
	e.deps.sweep()
	if strings.Contains(e.audit.String(), `"event":"deadline"`) {
		t.Fatal("deadline checked before its grace")
	}
	advance(deadlineGrace)
	e.deps.sweep()
	if !strings.Contains(e.audit.String(), `"event":"deadline","outcome":"not_reverted"`) {
		t.Fatalf("audit: %s", e.audit)
	}

	dev.Expire()
	applied(t, e)
	dev.Down = true
	advance(5*time.Minute + deadlineGrace)
	e.deps.sweep()
	if !strings.Contains(e.audit.String(), `"event":"deadline","outcome":"unreachable"`) {
		t.Fatalf("audit: %s", e.audit)
	}
}

func TestChangeLimits(t *testing.T) {
	e, _ := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	for _, m := range []int{1, 16} {
		if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": planned(t, e), "reason": "r", "revert_minutes": m}); errText == "" {
			t.Errorf("revert_minutes %d accepted", m)
		}
	}
	first, second := planned(t, e), planned(t, e)
	if out, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": first, "reason": "r", "revert_minutes": 15}); errText != "" {
		t.Fatalf("%v %s", out, errText)
	}
	if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": second, "reason": "r"}); !strings.Contains(errText, "in progress") {
		t.Fatalf("second apply on a busy device: %s", errText)
	}
	if !strings.Contains(e.audit.String(), `"revert_minutes":15`) {
		t.Fatal("revert_minutes not audited")
	}
	for _, a := range []string{"apply", "confirm", "rollback"} {
		if _, errText := e.call(t, "network_change", map[string]any{"action": a, "plan_id": "x", "change_id": "x"}); !strings.Contains(errText, "reason") {
			t.Errorf("%s without reason: %s", a, errText)
		}
	}
}

func TestChangeSaveGate(t *testing.T) {
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}})
	res, _ := e.cs.ListTools(context.Background(), nil)
	i := slices.IndexFunc(res.Tools, func(tl *mcp.Tool) bool { return tl.Name == "network_change" })
	if s := string(must(json.Marshal(res.Tools[i].InputSchema))); strings.Contains(s, `"save"`) || !strings.Contains(s, `"rollback"`) {
		t.Fatalf("save in the schema without --allow-save: %s", s)
	}
	if _, err := e.deps.save(context.Background(), "", "", ChangeInput{Action: "save", Device: "dev1", Reason: "r"}); err == nil || !strings.Contains(err.Error(), "--allow-save") {
		t.Fatalf("direct save: %v", err)
	}

	e, dev = startChange(t, setup{allowConfig: true, allowSave: true, rules: []config.Rule{writeRule}})
	save := map[string]any{"action": "save", "device": "dev1", "reason": "r"}
	if _, errText := e.call(t, "network_change", save); !strings.Contains(errText, "no change confirmed") {
		t.Fatalf("save with nothing confirmed: %s", errText)
	}
	id := applied(t, e)["change_id"].(string)
	e.call(t, "network_change", act("confirm", id))
	applied(t, e)
	if _, errText := e.call(t, "network_change", save); !strings.Contains(errText, "in progress") {
		t.Fatalf("save while pending: %s", errText)
	}
	if _, errText := e.call(t, "network_change", map[string]any{"action": "save", "device": "dev1"}); !strings.Contains(errText, "reason") {
		t.Fatalf("save without reason: %s", errText)
	}
	if strings.Contains(dev.Startup, "vlan 10") || slices.ContainsFunc(dev.Log(), func(l string) bool { return strings.Contains(l, "copy") }) {
		t.Fatal("a refused save reached the device")
	}
}

func TestChangeSaveDevicePending(t *testing.T) {
	e, _ := startChange(t, setup{allowConfig: true, allowSave: true, rules: []config.Rule{writeRule}})
	id := applied(t, e)["change_id"].(string)
	e.call(t, "network_change", act("confirm", id))
	startTimer(t, e) // another process's change
	if _, errText := e.call(t, "network_change", map[string]any{"action": "save", "device": "dev1", "reason": "r"}); !strings.Contains(errText, "pending on the device") {
		t.Fatalf("save under a device timer: %s", errText)
	}
}

// flaky fails every write once armed.
type flaky struct {
	buf  bytes.Buffer
	fail atomic.Bool
}

func (f *flaky) Write(b []byte) (int, error) {
	if f.fail.Load() {
		return 0, errors.New("disk full")
	}
	return f.buf.Write(b)
}

func TestChangeApplyAuditFailClosed(t *testing.T) {
	w := &flaky{}
	e, dev := startChange(t, setup{allowConfig: true, rules: []config.Rule{writeRule}, auditW: w})
	id := planned(t, e)
	w.fail.Store(true)
	if _, errText := e.call(t, "network_change", map[string]any{"action": "apply", "plan_id": id, "reason": "r"}); !strings.Contains(errText, "audit") {
		t.Fatalf("apply with a failing audit log: %q", errText)
	}
	if configMode(dev) {
		t.Fatalf("config mode entered: %q", dev.Log())
	}

	w.fail.Store(false)
	cid := applied(t, e)["change_id"].(string)
	w.fail.Store(true)
	if _, errText := e.call(t, "network_change", act("confirm", cid)); !strings.Contains(errText, "audit") || !dev.Pending() {
		t.Fatalf("confirm with a failing audit log: %q", errText)
	}
}
