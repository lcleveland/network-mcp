package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/network-mcp/internal/config"
	"github.com/lcleveland/network-mcp/internal/inventory"
	"github.com/lcleveland/network-mcp/internal/tools"
)

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func TestHTTP(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := &config.Config{Path: "/mcp", HTTPAuthToken: "s3cret-token-value", RequestTimeout: time.Second}
	inv, _ := inventory.Load(nil)
	s, _ := New(tools.Deps{Config: cfg, Inv: inv, Log: log})
	srv := httptest.NewServer(Handler(cfg, s, log))
	defer srv.Close()

	if r, err := http.Get(srv.URL + "/healthz"); err != nil || r.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", r, err)
	}
	if r, err := http.Post(srv.URL+"/mcp", "application/json", nil); err != nil || r.StatusCode != 401 {
		t.Fatalf("no bearer: %v %v", r.StatusCode, err)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 401 {
		t.Fatalf("wrong bearer: %v %v", r.StatusCode, err)
	}

	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{"s3cret-token-value"}},
	}, nil)
	if err != nil {
		t.Fatalf("initialize with bearer: %v", err)
	}
	res, err := cs.ListTools(ctx, nil)
	if err != nil || len(res.Tools) == 0 {
		t.Fatalf("list tools: %v", err)
	}
	cs.Close()

	if strings.Contains(logs.String(), "s3cret-token-value") {
		t.Fatalf("token in logs: %s", logs.String())
	}
}
