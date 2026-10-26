package server

import (
	"strings"
	"testing"

	"github.com/lcleveland/network-mcp/internal/tools"
)

func TestInstructionsWarnAboutUntrusted(t *testing.T) {
	if !strings.Contains(instructions, tools.UntrustedNote) {
		t.Fatal("server instructions lack the _untrusted note")
	}
}
