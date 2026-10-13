package report

import (
	"html/template"
	"io"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// WriteHTML renders a self-contained HTML report (PRD §11 M4: HTML report).
func WriteHTML(w io.Writer, res *model.ScanResult) error {
	return htmlTmpl.Execute(w, res)
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sevClass": func(s model.Severity) string { return string(s) },
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>issue-detector report</title>
<style>
:root{color-scheme:light dark}
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px;background:#0d1117;color:#e6edf3}
h1{font-size:20px;margin:0 0 4px}
.meta{color:#8b949e;margin-bottom:16px}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}
th{position:sticky;top:0;background:#161b22}
.sev{font-weight:600;text-transform:uppercase;font-size:12px;padding:2px 8px;border-radius:10px}
.critical{background:#6e0b0b;color:#ffd7d7}.high{background:#8a2c0d;color:#ffe0d0}
.medium{background:#7a5b00;color:#fff3cd}.low{background:#1f4d2e;color:#d4f7dd}.info{background:#1f3a5f;color:#d8e9ff}
code{background:#161b22;padding:1px 5px;border-radius:4px}
.file{color:#8b949e}.fix{color:#7ee787}.refs a{color:#58a6ff;display:block}
.summary span{margin-right:14px}
.badge{font-size:11px;background:#1f3a5f;color:#d8e9ff;border-radius:8px;padding:1px 6px;margin-left:6px}
</style>
</head>
<body>
<h1>{{.Tool.Name}} v{{.Tool.Version}}</h1>
<div class="meta">scan {{.ScanID}} · root {{.Root}} · {{.DurationMs}} ms</div>
<div class="summary">
  <span>files: {{.Summary.FilesEnumerated}}</span>
  <span>findings: {{.Summary.Findings}}</span>
  {{range $s, $n := .Summary.BySeverity}}<span class="sev {{sevClass $s}}">{{$s}} {{$n}}</span>{{end}}
</div>
<h2>Findings</h2>
{{if not .Findings}}<p>No findings.</p>{{end}}
{{if .Findings}}
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Detail</th></tr></thead>
<tbody>
{{range .Findings}}
<tr>
  <td><span class="sev {{sevClass .Severity}}">{{.Severity}}</span></td>
  <td><code>{{.RuleID}}</code><div class="file">{{.Category}}</div></td>
  <td class="file">{{.File}}:{{.Line}}{{if .InDiff}} <span class="badge">in diff</span>{{end}}</td>
  <td>
    <strong>{{.Title}}</strong>
    <div>{{.Message}}</div>
    {{if .Snippet}}<div><code>{{.Snippet}}</code></div>{{end}}
    {{if .FixHint}}<div class="fix">fix: {{.FixHint}}</div>{{end}}
    {{if .References}}<div class="refs">{{range .References}}<a href="{{.}}">{{.}}</a>{{end}}</div>{{end}}
  </td>
</tr>
{{end}}
</tbody>
</table>
{{end}}
</body>
</html>
`))
