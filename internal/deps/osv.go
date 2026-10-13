package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// DefaultOSVEndpoint is the public OSV API.
const DefaultOSVEndpoint = "https://api.osv.dev"

// Client queries OSV for known vulnerabilities.
type Client struct {
	HTTP    *http.Client
	BaseURL string
}

// NewClient returns a client with sane timeouts.
func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, BaseURL: DefaultOSVEndpoint}
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// Lookup returns DEP-001 findings for vulnerable dependencies. It batches the
// query, then fetches details for each reported advisory.
func (c *Client) Lookup(ctx context.Context, in []model.Dependency) ([]model.Finding, error) {
	if len(in) == 0 {
		return nil, nil
	}
	// Deduplicate by ecosystem/name/version.
	type key struct{ eco, name, ver string }
	uniq := map[key]model.Dependency{}
	var order []key
	for _, d := range in {
		if d.Name == "" || d.Version == "" {
			continue
		}
		k := key{d.Ecosystem, d.Name, d.Version}
		if _, ok := uniq[k]; !ok {
			uniq[k] = d
			order = append(order, k)
		}
	}
	if len(order) == 0 {
		return nil, nil
	}

	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	queries := make([]query, len(order))
	for i, k := range order {
		queries[i].Package.Name = k.name
		queries[i].Package.Ecosystem = k.eco
		queries[i].Version = k.ver
	}

	body, _ := json.Marshal(map[string]any{"queries": queries})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv querybatch: %s", resp.Status)
	}
	var batch struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, err
	}

	// Collect unique advisory IDs.
	idSet := map[string]bool{}
	for _, r := range batch.Results {
		for _, v := range r.Vulns {
			idSet[v.ID] = true
		}
	}
	details := c.fetchDetails(ctx, idSet)

	var findings []model.Finding
	for i, r := range batch.Results {
		if i >= len(order) {
			break
		}
		dep := uniq[order[i]]
		for _, v := range r.Vulns {
			d := details[v.ID]
			findings = append(findings, vulnFinding(dep, v.ID, d))
		}
	}
	return findings, nil
}

func (c *Client) fetchDetails(ctx context.Context, ids map[string]bool) map[string]osvVuln {
	out := make(map[string]osvVuln, len(ids))
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)

	for _, id := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := c.fetchOne(ctx, id)
			if err != nil {
				return
			}
			mu.Lock()
			out[id] = v
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

func (c *Client) fetchOne(ctx context.Context, id string) (osvVuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return osvVuln{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return osvVuln{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return osvVuln{}, fmt.Errorf("osv vulns: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return osvVuln{}, err
	}
	var v osvVuln
	if err := json.Unmarshal(data, &v); err != nil {
		return osvVuln{}, err
	}
	return v, nil
}

func vulnFinding(dep model.Dependency, id string, v osvVuln) model.Finding {
	sev := osvSeverity(v)
	title := "Vulnerable dependency: " + dep.Name + "@" + dep.Version
	msg := strings.TrimSpace(v.Summary)
	if msg == "" {
		msg = "Dependency " + dep.Name + " versi " + dep.Version + " memiliki kerentanan yang diketahui."
	}
	fix := "Tingkatkan " + dep.Name + " ke versi yang tidak rentan."
	var refs []string
	for _, r := range v.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	refs = append(refs, "https://osv.dev/vulnerability/"+id)
	return model.Finding{
		RuleID: "DEP-001", Category: model.CategoryDependency, Severity: sev,
		Title: title, Message: msg + " [" + id + "]", FixHint: fix,
		File: dep.File, Source: model.SourceRule, Confidence: 0.9,
		References: refs,
	}
}

func osvSeverity(v osvVuln) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(v.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MODERATE", "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	}
	// Fall back to a CVSS base score if present in the score vector's trailing metric.
	for _, s := range v.Severity {
		if score := cvssBase(s.Score); score > 0 {
			switch {
			case score >= 9.0:
				return model.SeverityCritical
			case score >= 7.0:
				return model.SeverityHigh
			case score >= 4.0:
				return model.SeverityMedium
			default:
				return model.SeverityLow
			}
		}
	}
	return model.SeverityMedium
}

// cvssBase extracts the trailing base score from a CVSS vector (e.g. ".../AV:N/..."), if present.
func cvssBase(score string) float64 {
	if !strings.HasPrefix(score, "CVSS:") {
		return 0
	}
	// OSV sometimes embeds the numeric score after the vector in parentheses.
	if i := strings.LastIndex(score, "("); i >= 0 {
		var f float64
		if _, err := fmt.Sscanf(score[i+1:], "%f", &f); err == nil {
			return f
		}
	}
	return 0
}
