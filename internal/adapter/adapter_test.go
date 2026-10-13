package adapter

import (
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestParseBandit(t *testing.T) {
	data := []byte(`{"results":[{"filename":"/proj/app.py","line_number":12,"issue_severity":"HIGH","issue_text":"Use of eval","test_id":"B307","test_name":"blacklist","more_info":"https://bandit/B307"}]}`)
	fs, err := parseBandit("/proj", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1, got %d", len(fs))
	}
	f := fs[0]
	if f.RuleID != "ADP-BANDIT-B307" || f.Severity != model.SeverityHigh || f.File != "app.py" || f.Line != 12 {
		t.Errorf("bad mapping: %+v", f)
	}
	if f.Source != model.SourceAdapter {
		t.Errorf("source = %s", f.Source)
	}
}

func TestParseSemgrep(t *testing.T) {
	data := []byte(`{"results":[{"check_id":"python.lang.security.audit.exec","path":"/proj/x.py","start":{"line":3},"extra":{"message":"eval usage","severity":"ERROR"}}]}`)
	fs, err := parseSemgrep("/proj", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != model.SeverityHigh || fs[0].File != "x.py" {
		t.Errorf("bad mapping: %+v", fs)
	}
}

func TestParsePipAudit(t *testing.T) {
	data := []byte(`{"dependencies":[{"name":"requests","version":"2.0.0","vulns":[{"id":"GHSA-x","description":"bad","fix_versions":["2.31.0"]}]}]}`)
	fs, err := parsePipAudit("/proj", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Category != model.CategoryDependency {
		t.Fatalf("bad mapping: %+v", fs)
	}
	if len(fs[0].References) == 0 {
		t.Error("expected a reference URL")
	}
}

func TestAvailabilityAbsent(t *testing.T) {
	a := Adapter{Name: "definitely-not-installed-xyz", Command: []string{"definitely-not-installed-xyz"}}
	if a.Available() {
		t.Error("absent binary reported available")
	}
}
