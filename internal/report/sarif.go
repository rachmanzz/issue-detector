package report

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// SARIF 2.1.0 minimal, valid document (PRD §11 M3: output SARIF).
const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool            `json:"tool"`
	Results           []sarifResult        `json:"results"`
	OriginalURIBaseID map[string]sarifBase `json:"originalUriBaseIds,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name,omitempty"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      *sarifText        `json:"fullDescription,omitempty"`
	Help                 *sarifText        `json:"help,omitempty"`
	DefaultConfiguration sarifConfig       `json:"defaultConfiguration"`
	Properties           map[string]string `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int        `json:"startLine"`
	Snippet   *sarifText `json:"snippet,omitempty"`
}

type sarifBase struct {
	URI string `json:"uri"`
}

// WriteSARIF renders res as a SARIF 2.1.0 document.
func WriteSARIF(w io.Writer, res *model.ScanResult) error {
	log := sarifLog{Schema: sarifSchema, Version: "2.1.0"}

	seen := map[string]bool{}
	var ruleList []sarifRule
	var results []sarifResult
	for _, f := range res.Findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ruleList = append(ruleList, sarifRule{
				ID:               f.RuleID,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  &sarifText{Text: f.Message},
				Help:             fixText(f.FixHint),
				DefaultConfiguration: sarifConfig{
					Level: sarifLevel(f.Severity),
				},
				Properties: map[string]string{"category": string(f.Category)},
			})
		}
		loc := sarifLocation{PhysicalLocation: sarifPhysical{
			ArtifactLocation: sarifArtifact{URI: fileURI(f.File), URIBaseID: "%SRCROOT%"},
			Region:           sarifRegion{StartLine: max(1, f.Line)},
		}}
		if s := strings.TrimSpace(f.Snippet); s != "" {
			loc.PhysicalLocation.Region.Snippet = &sarifText{Text: s}
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: f.Message},
			Locations: []sarifLocation{loc},
		})
	}

	log.Runs = []sarifRun{{
		Tool: sarifTool{Driver: sarifDriver{
			Name:    res.Tool.Name,
			Version: res.Tool.Version,
			Rules:   ruleList,
		}},
		Results:           results,
		OriginalURIBaseID: map[string]sarifBase{"%SRCROOT%": {URI: fileBase(res.Root)}},
	}}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func fixText(fix string) *sarifText {
	if fix == "" {
		return nil
	}
	return &sarifText{Text: fix}
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// fileURI makes a repo-relative path SARIF-safe (forward slashes).
func fileURI(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

func fileBase(root string) string {
	if root == "" {
		return ""
	}
	p := strings.ReplaceAll(root, "\\", "/")
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return "file://" + p
}
