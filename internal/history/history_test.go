package history

import (
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func res(id string, findings int, crit int, score float64) *model.ScanResult {
	r := &model.ScanResult{
		ScanID: id, Root: "/p",
		Summary: model.Summary{
			FilesEnumerated: 5, Findings: findings,
			BySeverity: map[model.Severity]int{model.SeverityCritical: crit},
		},
	}
	for i := 0; i < findings; i++ {
		r.Findings = append(r.Findings, model.Finding{Severity: model.SeverityHigh, PriorityScore: score})
	}
	return r
}

func TestRecordAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.Record(res("s1", 3, 1, 50)); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(res("s2", 1, 0, 70)); err != nil {
		t.Fatal(err)
	}

	snaps, err := store.Scans(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("want 2 snapshots, got %d", len(snaps))
	}
	// Newest first.
	if snaps[0].ScanID != "s2" {
		t.Errorf("expected newest first, got %s", snaps[0].ScanID)
	}
	if snaps[0].Findings != 1 || snaps[0].AvgScore != 70 {
		t.Errorf("bad snapshot: %+v", snaps[0])
	}

	// Idempotent per scan_id.
	if err := store.Record(res("s2", 9, 9, 10)); err != nil {
		t.Fatal(err)
	}
	snaps, _ = store.Scans(0)
	if len(snaps) != 2 {
		t.Errorf("re-record should upsert, got %d rows", len(snaps))
	}
}
