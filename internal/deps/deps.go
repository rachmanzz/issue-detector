// Package deps discovers dependencies from common manifests/lockfiles and maps
// them to OSV for CVE lookup (PRD §4.6 Supply Chain). Discovery is offline and
// deterministic; only the OSV lookup touches the network.
package deps

import (
	"encoding/json"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/model"
)

// Result holds discovered dependencies plus manifest hygiene findings.
type Result struct {
	Deps     []model.Dependency
	Findings []model.Finding
}

// Discover parses themanifests among entries.
func Discover(entries []fetcher.Entry) Result {
	var res Result
	have := map[string]bool{}
	for _, e := range entries {
		have[strings.ToLower(path.Base(e.RelPath))] = true
	}

	for _, e := range entries {
		base := strings.ToLower(path.Base(e.RelPath))
		switch base {
		case "go.mod":
			res.Deps = append(res.Deps, parseGoMod(e)...)
			if !have["go.sum"] {
				res.Findings = append(res.Findings, lockfileFinding("go.sum", e.RelPath))
			}
		case "package.json":
			deps, unpinned := parsePackageJSON(e)
			res.Deps = append(res.Deps, deps...)
			res.Findings = append(res.Findings, unpinned...)
			if !have["package-lock.json"] && !have["yarn.lock"] && !have["pnpm-lock.yaml"] {
				res.Findings = append(res.Findings, lockfileFinding("package-lock.json / yarn.lock / pnpm-lock.yaml", e.RelPath))
			}
		case "requirements.txt":
			deps, unpinned := parseRequirements(e)
			res.Deps = append(res.Deps, deps...)
			res.Findings = append(res.Findings, unpinned...)
		}
	}
	return res
}

var goRequireLine = regexp.MustCompile(`^\s*([^\s/][^\s]*)\s+(v[0-9][^\s]*)`)

func parseGoMod(e fetcher.Entry) []model.Dependency {
	data, err := os.ReadFile(e.Path)
	if err != nil {
		return nil
	}
	var out []model.Dependency
	inRequire := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		line = strings.TrimPrefix(line, "require ")
		if !inRequire && !strings.HasPrefix(raw, "require ") {
			continue
		}
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if m := goRequireLine.FindStringSubmatch(line); m != nil {
			out = append(out, model.Dependency{Ecosystem: "Go", Name: m[1], Version: m[2], File: e.RelPath})
		}
	}
	return out
}

func parsePackageJSON(e fetcher.Entry) ([]model.Dependency, []model.Finding) {
	data, err := os.ReadFile(e.Path)
	if err != nil {
		return nil, nil
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, nil
	}
	var deps []model.Dependency
	var findings []model.Finding
	add := func(m map[string]string) {
		for name, ver := range m {
			deps = append(deps, model.Dependency{Ecosystem: "npm", Name: name, Version: cleanNPM(ver), File: e.RelPath})
			if !isExact(ver) {
				findings = append(findings, unpinnedFinding(name, ver, e.RelPath))
			}
		}
	}
	add(pkg.Dependencies)
	add(pkg.DevDependencies)
	add(pkg.OptionalDependencies)
	return deps, findings
}

func cleanNPM(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=< ")
	if i := strings.IndexAny(v, " |"); i >= 0 {
		v = v[:i]
	}
	return v
}

var reqLine = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s;#]+)?`)

func parseRequirements(e fetcher.Entry) ([]model.Dependency, []model.Finding) {
	data, err := os.ReadFile(e.Path)
	if err != nil {
		return nil, nil
	}
	var deps []model.Dependency
	var findings []model.Finding
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, op, ver := m[1], m[2], m[3]
		deps = append(deps, model.Dependency{Ecosystem: "PyPI", Name: name, Version: ver, File: e.RelPath})
		if op != "==" {
			findings = append(findings, unpinnedFinding(name, line, e.RelPath))
		}
	}
	return deps, findings
}

func isExact(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && !strings.ContainsAny(v, "^~*>=<| ")
}

func unpinnedFinding(name, spec, file string) model.Finding {
	return model.Finding{
		RuleID: "DEP-003", Category: model.CategoryDependency, Severity: model.SeverityLow,
		Title: "Dependency not pinned", Message: "Dependency '" + name + "' tidak di-pin ke versi pasti (" + spec + ").",
		FixHint: "Pin ke versi pasti / gunakan lockfile agar build reprodusibel.",
		File:    file, Source: model.SourceRule, Confidence: 0.5,
	}
}

func lockfileFinding(want, file string) model.Finding {
	return model.Finding{
		RuleID: "DEP-002", Category: model.CategoryDependency, Severity: model.SeverityLow,
		Title: "Lockfile tidak ada", Message: "Manifest " + file + " tanpa lockfile (" + want + ") — build tidak reprodusibel.",
		FixHint: "Commit lockfile ke repository.",
		File:    file, Source: model.SourceRule, Confidence: 0.5,
	}
}
