package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/rachmanzz/issue-detector/internal/model"
)

func testApp(t *testing.T, root, baselinePath string) *fiber.App {
	t.Helper()
	srv := New(Options{Root: root, BaselinePath: baselinePath})
	return srv.App()
}

func TestTokenAuth(t *testing.T) {
	srv := New(Options{Root: t.TempDir(), Token: "sekret"})
	app := srv.App()

	noAuth, _ := app.Test(newReq(http.MethodGet, "/api/rules", ""))
	defer noAuth.Body.Close()
	if noAuth.StatusCode != http.StatusUnauthorized {
		t.Errorf("tanpa token harus 401, got %d", noAuth.StatusCode)
	}

	okReq := newReq(http.MethodGet, "/api/rules", "")
	okReq.Header.Set("Authorization", "Bearer sekret")
	ok, _ := app.Test(okReq)
	defer ok.Body.Close()
	if ok.StatusCode != 200 {
		t.Errorf("dengan token harus 200, got %d", ok.StatusCode)
	}
}

func TestScanEngineResult(t *testing.T) {
	root := t.TempDir()
	srv := New(Options{Root: root})
	res, err := srv.scan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.SchemaVersion != "1" || res.Summary.FilesEnumerated != 0 {
		t.Errorf("bad scan result: %+v", res.Summary)
	}
}

func TestRulesAndIndex(t *testing.T) {
	app := testApp(t, t.TempDir(), filepath.Join(t.TempDir(), "b.json"))

	rules, _ := app.Test(newReq(http.MethodGet, "/api/rules", ""))
	defer rules.Body.Close()
	if rules.StatusCode != 200 {
		t.Errorf("/api/rules status %d", rules.StatusCode)
	}
	var list map[string]any
	if err := json.NewDecoder(rules.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if _, ok := list["rules"]; !ok {
		t.Error("rules payload missing")
	}

	idx, _ := app.Test(newReq(http.MethodGet, "/", ""))
	defer idx.Body.Close()
	body, _ := io.ReadAll(idx.Body)
	if !strings.Contains(string(body), "issue-detector") {
		t.Error("index page missing")
	}
}

func TestOriginGuard(t *testing.T) {
	app := testApp(t, t.TempDir(), filepath.Join(t.TempDir(), "b.json"))
	req := newReq(http.MethodPost, "/api/triage", `{}`)
	req.Header.Set("Origin", "http://evil.example")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST should be 403, got %d", resp.StatusCode)
	}
}

func TestTriagePersistsBaseline(t *testing.T) {
	base := filepath.Join(t.TempDir(), "bl.json")
	app := testApp(t, t.TempDir(), base)

	req := newReq(http.MethodPost, "/api/triage",
		`{"rule_id":"SECRET-001","file":"a.go","snippet":"x"}`)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	data, err := os.ReadFile(base)
	if err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
	if !strings.Contains(string(data), "fingerprints") {
		t.Errorf("baseline content unexpected: %s", data)
	}
}

func newReq(method, path, body string) *http.Request {
	req, _ := http.NewRequest(method, path, strings.NewReader(body))
	return req
}

// TestFilterFindingsIsPure guards roast v1: filtering must never mutate the
// stored scan result (shared backing array).
func TestFilterFindingsIsPure(t *testing.T) {
	app := fiber.New()
	app.Get("/t", func(c fiber.Ctx) error {
		fs := []model.Finding{
			{RuleID: "X", Severity: model.SeverityCritical, File: "a.go"},
			{RuleID: "Y", Severity: model.SeverityInfo, File: "a.go"},
		}
		out := filterFindings(fs, c)
		if len(fs) != 2 || fs[1].RuleID != "Y" {
			t.Errorf("input slice dimutasi: %+v", fs)
		}
		if len(out) != 1 {
			t.Errorf("filter salah: %+v", out)
		}
		return c.JSON(fiber.Map{"in": len(fs), "out": len(out)})
	})
	resp, _ := app.Test(newReq(http.MethodGet, "/t?severity_min=critical", ""))
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestRuleLab(t *testing.T) {
	app := testApp(t, t.TempDir(), filepath.Join(t.TempDir(), "b.json"))
	body := `{"yaml":"id: LAB-1\ncategory: security\nseverity: high\nmatch: {kind: regex, pattern: 'os\\.system'}\nlanguages: [python]","language":"python","code":"import os\nos.system(cmd)\n"}`
	req := newReq(http.MethodPost, "/api/rules/test", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["rule_id"] != "LAB-1" {
		t.Errorf("rule_id = %v", out["rule_id"])
	}
	matches, ok := out["matches"].([]any)
	if !ok || len(matches) != 1 {
		t.Errorf("want 1 match, got %v", out["matches"])
	}
}

func TestRuleLabInvalid(t *testing.T) {
	app := testApp(t, t.TempDir(), filepath.Join(t.TempDir(), "b.json"))
	req := newReq(http.MethodPost, "/api/rules/test", `{"yaml":"bad"}`)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("invalid rule should 400, got %d", resp.StatusCode)
	}
}
