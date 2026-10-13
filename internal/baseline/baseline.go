// Package baseline stores a set of accepted findings so CI can fail only on
// *new* issues (PRD §11 M3: baseline). Fingerprints are stable across line
// shifts: rule + file + hash of the normalized snippet.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

const version = 1

// Set is a collection of finding fingerprints.
type Set map[string]struct{}

// Fingerprint derives a stable identity for a finding.
//
// Findings that carry a snippet stay line-independent (a white-space shift does
// not resurrect them). File-level findings (empty snippet, e.g. git/dep at
// line 0) hash title+reference context instead of the empty string, so distinct
// findings in the same file do not collide (PRD §11 M3; roast v10).
func Fingerprint(f model.Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", f.RuleID, f.File)
	if s := normalize(f.Snippet); s != "" {
		fmt.Fprintf(h, "s\x00%s", s)
	} else {
		ref := ""
		if len(f.References) > 0 {
			ref = f.References[0]
		}
		fmt.Fprintf(h, "l\x00%s\x00%s", f.Title, ref)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

type doc struct {
	Version      int      `json:"version"`
	Fingerprints []string `json:"fingerprints"`
}

// Save writes the fingerprints of every finding in res to path.
func Save(path string, res *model.ScanResult) error {
	seen := map[string]struct{}{}
	for _, f := range res.Findings {
		seen[Fingerprint(f)] = struct{}{}
	}
	fps := make([]string, 0, len(seen))
	for fp := range seen {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	data, err := json.MarshalIndent(doc{Version: version, Fingerprints: fps}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Add unions the given fingerprints into the baseline file at path.
func Add(path string, fingerprints []string) error {
	set, err := Load(path)
	if err != nil {
		return err
	}
	for _, fp := range fingerprints {
		if fp != "" {
			set[fp] = struct{}{}
		}
	}
	fps := make([]string, 0, len(set))
	for fp := range set {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	data, err := json.MarshalIndent(doc{Version: version, Fingerprints: fps}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Load reads a baseline file. A missing file yields an empty set (not an error).
func Load(path string) (Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Set{}, nil
		}
		return nil, err
	}
	var d doc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	set := make(Set, len(d.Fingerprints))
	for _, fp := range d.Fingerprints {
		set[fp] = struct{}{}
	}
	return set, nil
}

// Filter drops findings present in the baseline, marking them in the summary.
// It returns the number removed.
func (s Set) Filter(res *model.ScanResult) int {
	if len(s) == 0 || res == nil {
		return 0
	}
	kept := res.Findings[:0]
	removed := 0
	for _, f := range res.Findings {
		if _, ok := s[Fingerprint(f)]; ok {
			removed++
			continue
		}
		kept = append(kept, f)
	}
	res.Findings = kept
	res.Summary.Findings = len(kept)
	res.Summary.Baselined = removed
	res.Summary.BySeverity = map[model.Severity]int{}
	for _, f := range kept {
		res.Summary.BySeverity[f.Severity]++
	}
	return removed
}
