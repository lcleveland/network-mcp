package sshfake

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sync"
)

// Nexus is the mutable state of a fake NX-OS, shared by every session of an
// Engine: the running and startup configs and the user checkpoints. Exec
// commands it does not know fall through to Engine.Commands.
//
// shortcut: replies follow Cisco's docs (research #5), not a lab
// transcript; re-record them on hardware.
type Nexus struct {
	Running       string
	Startup       string
	Errors        map[string]string // config line -> its error reply; the line is not applied
	RollbackReply string            // when set, rollback prints it and changes nothing
	Down          bool              // sessions close before the first prompt

	mu          sync.Mutex
	sessions    int
	checkpoints map[string]string // name -> running config when taken
	log         []string
}

const rollbackOK = "Note: Applying config parallelly may fail Rollback verification\nCollecting Running-Config\n" +
	"#Generating Rollback Patch\nExecuting Rollback Patch\nGenerating Running-config for verification\n" +
	"Generating Patch for verification\nVerification is Successful.\n\nRollback completed successfully.\n"

var nxCheckpoint = regexp.MustCompile(`^(checkpoint|no checkpoint|rollback running-config checkpoint|show diff rollback-patch checkpoint) (\S+)(?: atomic| running-config)?$`)

// Checkpoint takes a checkpoint, as another process or operator would.
func (n *Nexus) Checkpoint(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.take(name)
}

func (n *Nexus) take(name string) {
	if n.checkpoints == nil {
		n.checkpoints = map[string]string{}
	}
	n.checkpoints[name] = n.Running
}

// Checkpoints lists the checkpoint names.
func (n *Nexus) Checkpoints() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Sorted(maps.Keys(n.checkpoints))
}

func (n *Nexus) Config() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Running
}

// Log returns every line received, each as "<session> <line>"; sessions count from 1.
func (n *Nexus) Log() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.log)
}

func (n *Nexus) open() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Down {
		return 0
	}
	n.sessions++
	return n.sessions
}

func (n *Nexus) handle(sid int, mode *string, cmd string, _ func(string) error) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.log = append(n.log, fmt.Sprintf("%d %s", sid, cmd))
	if *mode != "" {
		return configLine(&n.Running, n.Errors, mode, cmd), true
	}
	if m := nxCheckpoint.FindStringSubmatch(cmd); m != nil {
		op, c := m[1], m[2]
		saved, ok := n.checkpoints[c]
		switch {
		case op == "checkpoint" && ok:
			return "ERROR: Checkpoint name " + c + " is already in use\n", true
		case op == "checkpoint" && len(n.checkpoints) >= 10:
			return "ERROR: Maximum number of checkpoints reached\n", true
		case op == "checkpoint":
			n.take(c)
			return "...........Done\n", true
		case !ok:
			return "ERROR: Checkpoint does not exist\n", true
		case op == "no checkpoint":
			delete(n.checkpoints, c)
			return "", true
		case op == "show diff rollback-patch checkpoint":
			return "#Generating Rollback Patch\n" + setDiff(saved, n.Running), true
		case n.RollbackReply != "":
			return n.RollbackReply, true
		}
		n.Running = saved
		return rollbackOK, true
	}
	switch {
	case cmd == "show running-config":
		return n.Running, true
	case cmd == "show startup-config":
		return n.Startup, true
	case cmd == "configure terminal":
		*mode = "config"
		return "Enter configuration commands, one per line. End with CNTL/Z.\n", true
	case cmd == "show checkpoint summary":
		out := "User Checkpoint Summary\n--------------------------------------------------------------------------------\n"
		for i, c := range slices.Sorted(maps.Keys(n.checkpoints)) {
			out += fmt.Sprintf("%d) %s:\nCreated by mcp-write\nCreated at Wed, 01:20:31 13 Nov 2019\nSize is %d bytes\nDescription: None\n\n", i+1, c, len(n.checkpoints[c]))
		}
		return out, true
	case cmd == "copy running-config startup-config":
		n.Startup = n.Running
		return "[########################################] 100%\nCopy complete, now saving to disk (please wait)...\nCopy complete.\n", true
	}
	return "", false
}
