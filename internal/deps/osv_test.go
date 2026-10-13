package deps

import (
	"math"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestCVSSScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // log4shell-like
		{"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3},
	}
	for _, c := range cases {
		got, ok := cvssScore(c.vector)
		if !ok {
			t.Errorf("%s: not parsed", c.vector)
			continue
		}
		if math.Abs(got-c.want) > 0.01 {
			t.Errorf("%s: got %.2f, want %.2f", c.vector, got, c.want)
		}
	}
	// Non-v3 vectors are not parsed.
	if _, ok := cvssScore("CVSS:4.0/AV:N/..."); ok {
		t.Error("CVSS v4 must not be parsed as v3")
	}
	if _, ok := cvssScore("nonsense"); ok {
		t.Error("garbage vector must not parse")
	}
}

func TestOSVSeverityFromVector(t *testing.T) {
	crit := osvSeverity(osvVuln{Severity: []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}})
	if crit != model.SeverityCritical {
		t.Errorf("9.8 vector should map to critical, got %s", crit)
	}
	// database_specific wins when present.
	high := osvSeverity(osvVuln{DatabaseSpecific: struct {
		Severity string `json:"severity"`
	}{Severity: "HIGH"}})
	if high != model.SeverityHigh {
		t.Errorf("expected HIGH, got %s", high)
	}
}
