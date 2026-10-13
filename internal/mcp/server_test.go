package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/config"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{Root: t.TempDir(), Config: config.Default(), BaselinePath: filepath.Join(t.TempDir(), "b.json"), Version: "0.1.0"}
}

func mkreq(id any, method string, params any) []byte {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	b, _ := json.Marshal(m)
	return b
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("bad response %s: %v", b, err)
	}
	return out
}

func TestInitialize(t *testing.T) {
	s := newTestServer(t)
	out := decode(t, s.Handle(mkreq(1, "initialize", map[string]any{})))
	if out["error"] != nil {
		t.Fatalf("initialize error: %v", out["error"])
	}
	res := out["result"].(map[string]any)
	info := res["serverInfo"].(map[string]any)
	if info["name"] != "issue-detector" {
		t.Errorf("serverInfo = %v", info)
	}
}

func TestToolsList(t *testing.T) {
	s := newTestServer(t)
	out := decode(t, s.Handle(mkreq(1, "tools/list", nil)))
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 6 {
		t.Fatalf("want 6 tools, got %d", len(tools))
	}
}

func TestToolScan(t *testing.T) {
	s := newTestServer(t)
	out := decode(t, s.Handle(mkreq(1, "tools/call", map[string]any{
		"name": "scan", "arguments": map[string]any{},
	})))
	if out["error"] != nil {
		t.Fatalf("scan error: %v", out["error"])
	}
	content := out["result"].(map[string]any)["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	var res map[string]any
	if err := json.Unmarshal([]byte(text), &res); err != nil {
		t.Fatalf("scan result not JSON: %v", err)
	}
	if res["scan_id"] == "" {
		t.Error("missing scan_id")
	}
}

func TestToolRulesList(t *testing.T) {
	s := newTestServer(t)
	out := decode(t, s.Handle(mkreq(1, "tools/call", map[string]any{"name": "rules_list", "arguments": map[string]any{}})))
	text := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if text == "" {
		t.Error("empty rules output")
	}
}

func TestToolUnknown(t *testing.T) {
	s := newTestServer(t)
	out := decode(t, s.Handle(mkreq(1, "tools/call", map[string]any{"name": "nope", "arguments": map[string]any{}})))
	if out["error"] == nil {
		t.Error("expected unknown-tool error")
	}
}

func TestNotificationNoResponse(t *testing.T) {
	s := newTestServer(t)
	if resp := s.Handle(mkreq(nil, "notifications/initialized", nil)); resp != nil {
		t.Errorf("notification should not respond, got %s", resp)
	}
}

func TestServeStdioRoundTrip(t *testing.T) {
	s := newTestServer(t)
	var stdin, stdout strings.Builder
	stdin.WriteString(string(mkreq(1, "tools/list", nil)) + "\n")
	if err := s.ServeStdio(context.Background(), strings.NewReader(stdin.String()), &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"tools"`) || !strings.Contains(stdout.String(), `"jsonrpc":"2.0"`) {
		t.Error("stdio output missing response")
	}
}
