// Package adapter runs optional external SAST/dependency tools as sandboxed
// subprocesses and normalizes their JSON output into findings (PRD §6.1/§6.2).
// Everything degrades gracefully: if a tool is absent the adapter is skipped.
package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// Sandbox selects the isolation level for adapter subprocesses (PRD §6.4).
type Sandbox string

const (
	SandboxNone    Sandbox = "none"    // timeout only
	SandboxDefault Sandbox = "default" // + prlimit (rlimit) + drop-uid when root
	SandboxStrict  Sandbox = "strict"  // + bubblewrap (no network, ro fs)
)

// Options configure adapter execution.
type Options struct {
	Root         string
	Sandbox      Sandbox
	Timeout      time.Duration
	UID, GID     uint32 // drop-to identity for default/strict when running as root
	DropIdentity bool
}

// Adapter is a named external tool with a JSON parser.
type Adapter struct {
	Name    string
	Command []string // argv; "{root}" is replaced with the scan root
	Parse   func(root string, stdout []byte) ([]model.Finding, error)
}

// Available reports whether the adapter's binary is on PATH.
func (a Adapter) Available() bool {
	if len(a.Command) == 0 {
		return false
	}
	_, err := exec.LookPath(a.Command[0])
	return err == nil
}

// Builtins returns the known adapters (PRD §6.1).
func Builtins() []Adapter {
	return []Adapter{
		{Name: "bandit", Command: []string{"bandit", "-r", "-f", "json", "{root}"}, Parse: parseBandit},
		{Name: "semgrep", Command: []string{"semgrep", "--json", "--quiet", "{root}"}, Parse: parseSemgrep},
		{Name: "pip-audit", Command: []string{"pip-audit", "-f", "json", "--path", "{root}"}, Parse: parsePipAudit},
	}
}

// Run executes the named adapters (or all builtins when names is empty) and
// returns their normalized findings. Absent tools are skipped silently.
func Run(ctx context.Context, names []string, opts Options) []model.Finding {
	if opts.Sandbox == "" {
		opts.Sandbox = SandboxDefault
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}
	selected := Builtins()
	if len(names) > 0 {
		want := map[string]bool{}
		for _, n := range names {
			want[strings.ToLower(strings.TrimSpace(n))] = true
		}
		var filtered []Adapter
		for _, a := range selected {
			if want[a.Name] {
				filtered = append(filtered, a)
			}
		}
		selected = filtered
	}

	var out []model.Finding
	for _, a := range selected {
		if !a.Available() {
			continue
		}
		findings, err := runOne(ctx, a, opts)
		if err != nil {
			continue // best-effort; a failing adapter never breaks the scan
		}
		out = append(out, findings...)
	}
	return out
}

func runOne(ctx context.Context, a Adapter, opts Options) ([]model.Finding, error) {
	argv := make([]string, len(a.Command))
	for i, c := range a.Command {
		argv[i] = strings.ReplaceAll(c, "{root}", opts.Root)
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	cmd, cleanup, err := buildCommand(ctx, argv, opts)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Tools like bandit/semgrep exit non-zero when findings exist; parse anyway.
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}
	}
	return a.Parse(opts.Root, stdout.Bytes())
}

// buildCommand wraps argv with the configured sandbox.
func buildCommand(ctx context.Context, argv []string, opts Options) (*exec.Cmd, func(), error) {
	cleanup := func() {}
	switch opts.Sandbox {
	case SandboxStrict:
		if _, err := exec.LookPath("bwrap"); err == nil {
			wrapped := append([]string{
				"bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
				"--unshare-net", "--unshare-pid", "--die-with-parent", "--",
			}, argv...)
			return exec.CommandContext(ctx, wrapped[0], wrapped[1:]...), cleanup, nil
		}
		fallthrough
	case SandboxDefault:
		if _, err := exec.LookPath("prlimit"); err == nil {
			wrapped := append([]string{
				"prlimit", "--cpu=120", "--as=2000000000", "--nofile=1024", "--nproc=256", "--",
			}, argv...)
			return exec.CommandContext(ctx, wrapped[0], wrapped[1:]...), cleanup, nil
		}
		fallthrough
	default:
		return exec.CommandContext(ctx, argv[0], argv[1:]...), cleanup, nil
	}
}

func relPath(root, p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		if r, err := filepath.Rel(root, p); err == nil {
			return filepath.ToSlash(r)
		}
	}
	return filepath.ToSlash(p)
}

func severityFromWord(w string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(w)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH", "ERROR":
		return model.SeverityHigh
	case "MEDIUM", "MODERATE", "WARNING":
		return model.SeverityMedium
	case "LOW", "INFO", "UNDEFINED":
		return model.SeverityLow
	default:
		return model.SeverityMedium
	}
}

// --- bandit -------------------------------------------------------------

type banditReport struct {
	Results []struct {
		Filename      string `json:"filename"`
		LineNumber    int    `json:"line_number"`
		IssueSeverity string `json:"issue_severity"`
		IssueText     string `json:"issue_text"`
		TestID        string `json:"test_id"`
		TestName      string `json:"test_name"`
		MoreInfo      string `json:"more_info"`
	} `json:"results"`
}

func parseBandit(root string, data []byte) ([]model.Finding, error) {
	var rep banditReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, r := range rep.Results {
		out = append(out, model.Finding{
			RuleID: "ADP-BANDIT-" + r.TestID, Category: model.CategorySecurity,
			Severity: severityFromWord(r.IssueSeverity), Title: "bandit: " + r.TestName,
			Message: r.IssueText, File: relPath(root, r.Filename), Line: r.LineNumber,
			Source: model.SourceAdapter, Confidence: 0.7,
			References: nonEmpty(r.MoreInfo),
		})
	}
	return out, nil
}

// --- semgrep ------------------------------------------------------------

type semgrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
}

func parseSemgrep(root string, data []byte) ([]model.Finding, error) {
	var rep semgrepReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, r := range rep.Results {
		out = append(out, model.Finding{
			RuleID: "ADP-SEMGREP-" + r.CheckID, Category: model.CategorySecurity,
			Severity: severityFromWord(r.Extra.Severity), Title: "semgrep: " + r.CheckID,
			Message: r.Extra.Message, File: relPath(root, r.Path), Line: r.Start.Line,
			Source: model.SourceAdapter, Confidence: 0.7,
		})
	}
	return out, nil
}

// --- pip-audit ----------------------------------------------------------

type pipAuditReport struct {
	Dependencies []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []struct {
			ID          string   `json:"id"`
			Description string   `json:"description"`
			FixVersions []string `json:"fix_versions"`
		} `json:"vulns"`
	} `json:"dependencies"`
}

func parsePipAudit(root string, data []byte) ([]model.Finding, error) {
	var rep pipAuditReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, d := range rep.Dependencies {
		for _, v := range d.Vulns {
			msg := v.Description
			if len(v.FixVersions) > 0 {
				msg += " (fix: " + strings.Join(v.FixVersions, ", ") + ")"
			}
			out = append(out, model.Finding{
				RuleID: "ADP-PIPAUDIT-" + v.ID, Category: model.CategoryDependency,
				Severity: model.SeverityHigh, Title: "pip-audit: " + d.Name + "@" + d.Version,
				Message: msg, File: "requirements.txt",
				Source: model.SourceAdapter, Confidence: 0.8,
				References: []string{"https://osv.dev/vulnerability/" + v.ID},
			})
		}
	}
	return out, nil
}

func nonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{s}
}
