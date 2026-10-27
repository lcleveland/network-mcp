// Package audit writes one JSON line per security-relevant event, to stderr
// (journald under systemd) by default.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	TS      time.Time `json:"ts"`
	Event   string    `json:"event"`
	Outcome string    `json:"outcome"`
	Error   string    `json:"error,omitempty"`
	Device  string    `json:"device,omitempty"`
	Address string    `json:"address,omitempty"`
	Command string    `json:"command,omitempty"`
	CredRef string    `json:"cred_ref,omitempty"` // the ref name, never its contents

	// write pipeline (#10 §8)
	MCPSession string   `json:"mcp_session,omitempty"`
	Client     string   `json:"client,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Platform   string   `json:"platform,omitempty"` // the driver
	HostKey    string   `json:"host_key,omitempty"`
	Username   string   `json:"username,omitempty"`
	PlanID     string   `json:"plan_id,omitempty"`
	Commands   []string `json:"commands,omitempty"` // redacted
	PreHash    string   `json:"pre_hash,omitempty"`
}

type Log struct {
	mu sync.Mutex
	w  io.Writer
}

func New(w io.Writer) *Log { return &Log{w: w} }

// Write returns the error so write paths can fail closed.
func (l *Log) Write(e Event) error {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.w.Write(append(b, '\n'))
	return err
}
