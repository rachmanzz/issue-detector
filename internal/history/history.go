// Package history persists scan snapshots in SQLite for `watch`/`trend`
// (PRD §11 M7). Uses the pure-Go modernc.org/sqlite driver (no CGO).
package history

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// Snapshot is one recorded scan.
type Snapshot struct {
	ScanID   string    `json:"scan_id"`
	Time     time.Time `json:"time"`
	Root     string    `json:"root"`
	Files    int       `json:"files"`
	Findings int       `json:"findings"`
	Critical int       `json:"critical"`
	High     int       `json:"high"`
	Medium   int       `json:"medium"`
	Low      int       `json:"low"`
	Info     int       `json:"info"`
	AvgScore float64   `json:"avg_score"`
}

// Store is a SQLite-backed scan history.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the history database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  root TEXT,
  files INTEGER,
  findings INTEGER,
  critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, info INTEGER,
  avg_score REAL
);
`

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Record stores a snapshot of res (idempotent per scan_id).
func (s *Store) Record(res *model.ScanResult) error {
	sum := res.Summary
	var total float64
	for _, f := range res.Findings {
		total += f.PriorityScore
	}
	avg := 0.0
	if len(res.Findings) > 0 {
		avg = total / float64(len(res.Findings))
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO scans
		 (scan_id, ts, root, files, findings, critical, high, medium, low, info, avg_score)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		res.ScanID, time.Now().UnixNano(), res.Root, sum.FilesEnumerated, sum.Findings,
		sum.BySeverity[model.SeverityCritical], sum.BySeverity[model.SeverityHigh],
		sum.BySeverity[model.SeverityMedium], sum.BySeverity[model.SeverityLow],
		sum.BySeverity[model.SeverityInfo], avg,
	)
	return err
}

// Scans returns up to limit snapshots, newest first (limit<=0 = all).
func (s *Store) Scans(limit int) ([]Snapshot, error) {
	q := `SELECT scan_id, ts, root, files, findings, critical, high, medium, low, info, avg_score
	      FROM scans ORDER BY ts DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var sn Snapshot
		var ts int64
		if err := rows.Scan(&sn.ScanID, &ts, &sn.Root, &sn.Files, &sn.Findings,
			&sn.Critical, &sn.High, &sn.Medium, &sn.Low, &sn.Info, &sn.AvgScore); err != nil {
			return nil, err
		}
		sn.Time = time.Unix(0, ts)
		out = append(out, sn)
	}
	return out, rows.Err()
}
