package sshfake

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Device is the mutable state of a fake IOS-XE, shared by every session of
// an Engine: the running and startup configs, the Rollback Confirmed Change
// revert timer and the configuration lock. Exec commands it does not know
// fall through to Engine.Commands.
//
// shortcut: replies and refusals follow Cisco's docs (research #5), not a
// lab transcript; re-record them on hardware.
type Device struct {
	Running        string // must hold "archive" with " path ..." for the revert timer
	Startup        string
	Errors         map[string]string // config line -> its % error reply; the line is not applied
	Locked         bool              // show configuration lock lists an owner
	SessionBound   bool              // configure confirm and revert work only in the session that started the timer
	Down           bool              // sessions close before the first prompt
	DriftOnConfirm string            // appended to Running when configure confirm succeeds (a concurrent change)

	mu       sync.Mutex
	sessions int
	timer    int               // session that started the pending timer; 0 none
	backup   string            // running config when the timer started
	files    map[string]string // flash: file name -> content (server-reverted snapshots)
	log      []string
}

const noTimer = "%No Rollback Confirmed Change pending\n"

var (
	revertTimer = regexp.MustCompile(`^configure terminal revert timer (\d+)$`)
	archivePath = regexp.MustCompile(`(?m)^archive\n(?: .*\n)*? path \S`)
	flashCmd    = regexp.MustCompile(`^(copy running-config|delete /force|configure replace|show archive config differences) flash:(\S+?)(?: force| system:running-config)?$`)
)

// Expire fires a pending revert timer, as the device does at its deadline.
func (d *Device) Expire() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != 0 {
		d.Running, d.timer = d.backup, 0
	}
}

// Put writes a flash: file, as another process or operator would.
func (d *Device) Put(name, content string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.put(name, content)
}

func (d *Device) put(name, content string) {
	if d.files == nil {
		d.files = map[string]string{}
	}
	d.files[name] = content
}

// Files lists the flash: file names.
func (d *Device) Files() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Sorted(maps.Keys(d.files))
}

// Pending reports whether a revert timer is running.
func (d *Device) Pending() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.timer != 0
}

// Config returns the running config.
func (d *Device) Config() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Running
}

// Log returns every line received, each as "<session> <line>"; sessions count from 1.
func (d *Device) Log() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.log)
}

// open numbers a new session, or returns 0 while the device is down.
func (d *Device) open() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Down {
		return 0
	}
	d.sessions++
	return d.sessions
}

func (d *Device) handle(sid int, mode *string, cmd string, ask func(string) error) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, fmt.Sprintf("%d %s", sid, cmd))
	if *mode != "" {
		return configLine(&d.Running, d.Errors, mode, cmd), true
	}
	refuse := func() string {
		switch {
		case d.timer == 0:
			return noTimer
		case d.SessionBound && d.timer != sid:
			return "%Rollback Confirmed Change: only the user who started the timer can change it\n"
		}
		return ""
	}
	if m := flashCmd.FindStringSubmatch(cmd); m != nil {
		op, name := m[1], m[2]
		saved, ok := d.files[name]
		switch {
		case op == "copy running-config":
			if ask("Destination filename ["+name+"]? ") != nil {
				return "", true
			}
			d.put(name, d.Running)
			return fmt.Sprintf("%d bytes copied in 0.123 secs (1000 bytes/sec)\n", len(d.Running)), true
		case !ok:
			return "%Error opening flash:" + name + " (No such file or directory)\n", true
		case op == "delete /force":
			delete(d.files, name)
			return "", true
		case op == "show archive config differences":
			return diff(saved, d.Running), true
		}
		d.Running = saved // configure replace
		return "Total number of passes: 1\nRollback Done\n", true
	}
	switch {
	case cmd == "dir flash:":
		out := "Directory of flash:/\n\n"
		for _, n := range slices.Sorted(maps.Keys(d.files)) {
			out += fmt.Sprintf("  1  -rw-  %d  Oct 27 2026 12:00:00 +00:00  %s\n", len(d.files[n]), n)
		}
		return out + "\n1621966848 bytes total (1015734272 bytes free)\n", true
	case cmd == "show running-config":
		return d.Running, true
	case cmd == "show startup-config":
		return d.Startup, true
	case cmd == "configure terminal":
		*mode = "config"
		return "Enter configuration commands, one per line.  End with CNTL/Z.\n", true
	case cmd == "show archive config rollback timer":
		if d.timer == 0 {
			return noTimer, true
		}
		return "Timer type: Revert timer\nTimer value: 5 min\nUser: mcp-write\n", true
	case cmd == "show configuration lock":
		out := "\nParser Configure Lock\n---------------------\n"
		if d.Locked {
			out += "Owner PID         : 10\nUser              : admin\nTTY               : 2\nType              : EXCLUSIVE\n"
		}
		return out, true
	case revertTimer.MatchString(cmd):
		switch {
		case !archivePath.MatchString(d.Running):
			return "%Archive path is not configured\n", true
		case d.timer != 0:
			return "%Rollback Confirmed Change is already pending\n", true
		}
		d.timer, d.backup, *mode = sid, d.Running, "config"
		return "Enter configuration commands, one per line.  End with CNTL/Z.\n", true
	case cmd == "configure confirm":
		if out := refuse(); out != "" {
			return out, true
		}
		d.timer = 0
		d.Running += d.DriftOnConfirm
		return "", true
	case cmd == "configure revert now":
		if out := refuse(); out != "" {
			return out, true
		}
		d.Running, d.timer = d.backup, 0
		return "Rollback Confirmed Change: Rolling back to the archived config\n", true
	case cmd == "show archive config differences":
		return diff(d.Startup, d.Running), true
	case cmd == "copy running-config startup-config":
		if ask("Destination filename [startup-config]? ") != nil {
			return "", true
		}
		d.Startup = d.Running
		return "Building configuration...\n[OK]\n", true
	}
	return "", false
}

// configLine applies one config-mode line to running, unless errs holds
// its error reply, and returns the reply.
func configLine(running *string, errs map[string]string, mode *string, cmd string) string {
	switch out, ok := errs[cmd]; {
	case cmd == "end":
		*mode = ""
	case ok:
		return out
	case cmd != "":
		ind := ""
		if *mode != "config" {
			ind = " "
		}
		*running += ind + cmd + "\n"
		if f := strings.Fields(cmd)[0]; f == "interface" || f == "vlan" || f == "router" || f == "archive" {
			*mode = "config-" + map[string]string{"interface": "if", "vlan": "vlan", "router": "router", "archive": "archive"}[f]
		} else if strings.HasPrefix(cmd, "ip dhcp pool ") {
			*mode = "dhcp-config" // not every submode starts with "config"
		}
	}
	return ""
}

// diff is a set difference shaped like IOS's contextual diff.
func diff(old, cur string) string {
	return "Contextual Config Diffs:\n" + setDiff(old, cur)
}

func setDiff(old, cur string) string {
	o, c := strings.Split(old, "\n"), strings.Split(cur, "\n")
	out := ""
	for _, l := range c {
		if l != "" && !slices.Contains(o, l) {
			out += "+" + l + "\n"
		}
	}
	for _, l := range o {
		if l != "" && !slices.Contains(c, l) {
			out += "-" + l + "\n"
		}
	}
	return out
}
