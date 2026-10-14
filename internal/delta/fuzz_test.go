package delta

import "testing"

// FuzzAddedLines exercises the line-diff used by delta scanning on untrusted
// text. It must never panic and must return well-formed ranges.
func FuzzAddedLines(f *testing.F) {
	f.Add("a\nb\nc\n", "a\nc\n")
	f.Add("", "")
	f.Add("x", "x\ny\nz")
	f.Fuzz(func(t *testing.T, oldText, newText string) {
		rs := addedLines(oldText, newText)
		for i, r := range rs {
			if r.Start < 1 || r.End < r.Start {
				t.Fatalf("bad range %+v", r)
			}
			if i > 0 && rs[i-1].End >= r.Start {
				t.Fatalf("ranges not ordered/merged: %+v", rs)
			}
		}
	})
}
