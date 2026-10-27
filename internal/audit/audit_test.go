package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWrite(t *testing.T) {
	var buf bytes.Buffer
	if err := New(&buf).Write(Event{Event: "read_gate", Outcome: "denied", Device: "dev1", Command: "debug all"}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil || m["outcome"] != "denied" || m["ts"] == nil || m["error"] != nil {
		t.Fatalf("line %q: %v", buf.String(), err)
	}
	if New(failWriter{}).Write(Event{Event: "x"}) == nil {
		t.Fatal("want the writer's error")
	}
}
