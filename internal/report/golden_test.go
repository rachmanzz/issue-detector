package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update regenerates golden files: go test ./internal/report -run Golden -update
var update = flag.Bool("update", false, "update golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s missing (run: go test ./internal/report -run Golden -update): %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s changed; review the diff and re-run with -update if intended", name)
	}
}

// TestJSONGolden locks the JSON report contract (schema_version=1).
func TestJSONGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "report.golden.json", buf.Bytes())
}

// TestSARIFGolden locks the SARIF 2.1.0 report contract.
func TestSARIFGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "report.golden.sarif", buf.Bytes())
}
