// Command record captures device output for fixtures through a running
// network-mcp server, so every capture passes the server's prefix, host-key
// and read gates and its redaction:
//
//	go run ./cmd/record -url http://127.0.0.1:8237/mcp -device NAME -out testdata/raw/<family>
//
// It calls network_show for every getter and writes each complete output to
// <out>/<getter>.txt (NX-OS JSON re-indented); an output cut at the server's
// 60 KiB limit is not written. sizes.tsv records every output's full size and
// call time, the running config's included (its content is never written).
// testdata/raw is gitignored: run cmd/sanitize before anything is committed.
// It is not part of the shipped package.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/platform"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8237/mcp", "network-mcp HTTP endpoint")
	tokenFile := flag.String("token-file", "", "file holding the server's bearer token, if it has one")
	device := flag.String("device", "", "inventory device name")
	out := flag.String("out", "", "directory for the captures, under testdata/raw")
	flag.Parse()
	if err := run(*url, *tokenFile, *device, *out); err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
}

func run(url, tokenFile, device, out string) error {
	if device == "" || out == "" {
		return errors.New("-device and -out are required")
	}
	hc := http.DefaultClient
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return err
		}
		hc = &http.Client{Transport: bearer{strings.TrimSpace(string(b))}}
	}
	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "record"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: hc}, nil)
	if err != nil {
		return err
	}
	defer cs.Close()
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	var sizes strings.Builder
	sizes.WriteString("name\tbytes\tcomplete\tms\n")
	call := func(name, tool string, args map[string]any) error {
		start := time.Now()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		ms := time.Since(start).Milliseconds()
		body, size, complete, err := capture(res)
		if err != nil {
			fmt.Fprintf(os.Stderr, "record: %s: %v\n", name, err)
			return nil // a getter the device does not support is not fatal
		}
		fmt.Fprintf(&sizes, "%s\t%d\t%t\t%d\n", name, size, complete, ms)
		if !complete || tool == "network_config" {
			return nil
		}
		return os.WriteFile(filepath.Join(out, name+".txt"), body, 0o600)
	}
	getters := platform.GetterNames(nil)
	slices.Sort(getters)
	for _, g := range slices.Compact(getters) {
		if err := call(g, "network_show", map[string]any{"device": device, "getter": g}); err != nil {
			return err
		}
	}
	if err := call("running-config", "network_config", map[string]any{"action": "get", "device": device, "source": "running"}); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "sizes.tsv"), []byte(sizes.String()), 0o600)
}

// capture turns a tool result into the bytes to save, the output's full size
// and whether the server returned all of it.
func capture(res *mcp.CallToolResult) ([]byte, int, bool, error) {
	if res.IsError {
		var msg []string
		for _, c := range res.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				msg = append(msg, t.Text)
			}
		}
		return nil, 0, false, errors.New(strings.Join(msg, "; "))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return nil, 0, false, err
	}
	var o struct {
		Output      string          `json:"output"`
		Data        json.RawMessage `json:"data"`
		DeviceError string          `json:"device_error"`
		Truncation  *struct {
			Total int `json:"total"`
		} `json:"_truncation"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, 0, false, err
	}
	if o.DeviceError != "" {
		return nil, 0, false, errors.New(o.DeviceError)
	}
	body := []byte(o.Output)
	if o.Data != nil {
		var buf bytes.Buffer
		if err := json.Indent(&buf, o.Data, "", "  "); err != nil {
			return nil, 0, false, err
		}
		body = buf.Bytes()
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		body = append(body, '\n')
	}
	if o.Truncation != nil {
		return body, max(o.Truncation.Total, len(body)), false, nil
	}
	return body, len(body), true, nil
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
