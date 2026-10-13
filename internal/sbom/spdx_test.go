package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestWriteSPDX(t *testing.T) {
	deps := []model.Dependency{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
		{Ecosystem: "Go", Name: "github.com/foo/bar", Version: "v1.2.3"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}, // duplicate
	}
	var buf bytes.Buffer
	if err := Write(&buf, model.ToolInfo{Name: "issue-detector", Version: "0.1.0"}, "/tmp/proj", deps); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v", doc["spdxVersion"])
	}
	pkgs := doc["packages"].([]any)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 unique packages, got %d", len(pkgs))
	}
	first := pkgs[0].(map[string]any)
	refs := first["externalRefs"].([]any)
	purl := refs[0].(map[string]any)["referenceLocator"].(string)
	if purl == "" {
		t.Errorf("missing purl")
	}
}
