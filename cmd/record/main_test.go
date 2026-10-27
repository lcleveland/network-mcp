package main

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCapture(t *testing.T) {
	for _, c := range []struct {
		name     string
		res      *mcp.CallToolResult
		body     string
		size     int
		complete bool
		err      bool
	}{
		{"text", &mcp.CallToolResult{StructuredContent: map[string]any{"output": "Version 1"}}, "Version 1\n", 10, true, false},
		{"nxos json", &mcp.CallToolResult{StructuredContent: map[string]any{"data": map[string]any{"a": 1}, "parsed": true}}, "{\n  \"a\": 1\n}\n", 13, true, false},
		{"cut at 60 KiB", &mcp.CallToolResult{StructuredContent: map[string]any{"output": "x", "_truncation": map[string]any{"reason": "bytes", "total": 90000}}}, "x\n", 90000, false, false},
		{"device error", &mcp.CallToolResult{StructuredContent: map[string]any{"device_error": "% Invalid input"}}, "", 0, false, true},
		{"tool error", &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "denied"}}}, "", 0, false, true},
	} {
		body, size, complete, err := capture(c.res)
		if string(body) != c.body || size != c.size || complete != c.complete || (err != nil) != c.err {
			t.Errorf("%s: %q %d %t %v", c.name, body, size, complete, err)
		}
	}
}
