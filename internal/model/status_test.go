package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestScanResultStatusSerialized guards that a partial scan is visible on the
// wire (so CI/UI/agents can distinguish it) while a complete one stays clean.
func TestScanResultStatusSerialized(t *testing.T) {
	b, err := json.Marshal(ScanResult{Status: StatusPartial, ScanErrors: []string{"boom"}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"status":"partial"`) {
		t.Errorf("partial status must be serialized: %s", s)
	}
	if !strings.Contains(s, `"scan_errors":["boom"]`) {
		t.Errorf("scan_errors must be serialized: %s", s)
	}

	// A complete result (empty status) must not advertise a status or errors.
	b2, err := json.Marshal(ScanResult{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b2), `"status"`) || strings.Contains(string(b2), `"scan_errors"`) {
		t.Errorf("complete result must omit status/scan_errors: %s", b2)
	}

	// Partial() helper.
	partial := &ScanResult{Status: StatusPartial}
	if !partial.Partial() {
		t.Errorf("Partial() must be true for StatusPartial")
	}
	var nilRes *ScanResult
	if nilRes.Partial() {
		t.Errorf("Partial() on nil must be false")
	}
}
