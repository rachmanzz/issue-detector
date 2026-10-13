// Package sbom exports an SPDX 2.3 JSON document from discovered dependencies
// (PRD §4.6 SBOM + license). License fields are NOASSERTION unless a manifest
// supplies them — full license resolution needs a registry/lockfile.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"strings"
	"time"

	"github.com/rachmanzz/issue-detector/internal/model"
)

type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string   `json:"name"`
	SPDXID           string   `json:"SPDXID"`
	VersionInfo      string   `json:"versionInfo,omitempty"`
	DownloadLocation string   `json:"downloadLocation"`
	LicenseConcluded string   `json:"licenseConcluded"`
	LicenseDeclared  string   `json:"licenseDeclared"`
	ExternalRefs     []extRef `json:"externalRefs,omitempty"`
}

type extRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// Write renders an SPDX 2.3 JSON SBOM for deps.
func Write(w io.Writer, tool model.ToolInfo, root string, deps []model.Dependency) error {
	doc := document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              path.Base(strings.TrimRight(root, "/")) + "-sbom",
		DocumentNamespace: namespace(tool, root),
		CreationInfo: creationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: " + tool.Name + "-" + tool.Version},
		},
	}

	seen := map[string]bool{}
	for _, d := range deps {
		id := spdxID(d)
		if seen[id] {
			continue
		}
		seen[id] = true
		p := spdxPackage{
			Name:             d.Name,
			SPDXID:           id,
			VersionInfo:      d.Version,
			DownloadLocation: "NOASSERTION",
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
		}
		if purl := purlFor(d); purl != "" {
			p.ExternalRefs = []extRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}}
		}
		doc.Packages = append(doc.Packages, p)
		doc.Relationships = append(doc.Relationships, relationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelatedSpdxElement: id,
			RelationshipType:   "DESCRIBES",
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func spdxID(d model.Dependency) string {
	raw := d.Ecosystem + "-" + d.Name + "-" + d.Version
	return "SPDXRef-Package-" + sanitize(raw)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

func namespace(tool model.ToolInfo, root string) string {
	sum := sha256.Sum256([]byte(root + "|" + tool.Version))
	return "https://github.com/rachmanzz/issue-detector/sbom/" + hex.EncodeToString(sum[:])[:16]
}

func purlFor(d model.Dependency) string {
	if d.Name == "" {
		return ""
	}
	typ := map[string]string{"Go": "golang", "npm": "npm", "PyPI": "pypi"}[d.Ecosystem]
	if typ == "" {
		typ = strings.ToLower(d.Ecosystem)
	}
	p := "pkg:" + typ + "/" + d.Name
	if d.Version != "" {
		p += "@" + d.Version
	}
	return p
}
