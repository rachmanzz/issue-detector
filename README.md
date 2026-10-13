# issue-detector

Detektor masalah kode untuk project kecil–menengah. Men-scan folder lokal atau repo remote (clone shallow), mendeteksi temuan berbasis baris, dan melaporkannya dalam format `text` atau `json`. Didesain agar mudah di-"dogfood" oleh tool AI sebagai loop *agent → review → fix*.

## Fitur

- **Fetcher**: scan folder lokal, atau repo git remote via clone shallow (`go-git`); hormati `.gitignore`/`.issue-detectorignore` dan direktori umum yang di-ignore (`node_modules`, `vendor`, dll.).
- **Pipeline paralel**: tiap file diproses sebagai task pada in-memory queue; eksekusi oleh worker engine, dengan fan-out per rule (sub-worker) dan priorititas (secret-like files lebih dulu). Render-an akhir aggregator bersifat deterministik (sort severity → file → line) dan idempoten vs retry queue.
- **Rules**: registry + matcher line-based & AST (tree-sitter: Go/Python/JavaScript), plus rule kustom YAML.
- **Config**: nilai bawaan, file `issue-detector.yaml`, dan override via flag CLI.
- **Exit codes**: cocok untuk CI gate (0/1/2).
- **CI**: GitHub Actions `govulncheck` otomatis di `push`/`PR`/weekly.

## Persyaratan

- Go 1.27.2+ (toolchain di-pin di `go.mod`)

## Build & Install

```sh
go build -o issue-detector ./cmd/issue-detector
```

Atau jalankan langsung:

```sh
go run ./cmd/issue-detector scan .
```

## Usage

```
issue-detector scan [path|--remote URL] [flags]
issue-detector baseline [path] [flags]
issue-detector rules list
issue-detector version
```

Contoh:

```sh
# Scan folder saat ini, pintasan ringkas
./issue-detector scan . --quiet

# Output JSON ke file
./issue-detector scan . --format json --output report.json

# Gate CI: gagal jika ada severity >= high
./issue-detector scan . --fail-on high

# Scan repo remote
./issue-detector scan --remote https://github.com/example/repo.git

# Abaikan pola tambahan + naikkan konkurensi
./issue-detector scan . --ignore "*.pb.go" --ignore vendor/ --jobs 8
```

### Flags utama

| Flag | Default | Keterangan |
| --- | --- | --- |
| `--format` | `text` | `text` \| `json` \| `sarif` \| `html` |
| `--output` | stdout | tulis ke file, `-` = stdout |
| `--remote` | – | URL remote untuk clone & scan |
| `--categories` | semua | filter kategori temuan |
| `--severity-min` | `info` | ambang minimal severity |
| `--fail-on` | `none` | exit code 1 jika ada severity ≥ ambang |
| `--config` | `issue-detector.yaml` | path config YAML |
| `--jobs` | `NumCPU` | worker paralel |
| `--sub-worker-limit` | 0 (`5`) | fan-out sub-worker per file |
| `--max-file-size` | 0 (`1 MiB`) | batas ukuran file (bytes) |
| `--timeout` | 0 | batas durasi scan (detik, 0 = tanpa batas) |
| `--quiet` | false | hanya temuan (tanpa log engine) |
| `--ignore` | – | pola ignore tambahan (bisa diulang) |
| `--base` | – | delta scan: hanya baris berubah sejak ref git |
| `--diff` | – | delta scan: dari file patch (`.diff`/`.patch`) |
| `--no-git` | false | lewati analisis kesehatan git |
| `--rules` | `--` | file/direktori rule YAML tambahan (bisa diulang) |
| `--baseline` | – | abaikan temuan yang sudah ada di file baseline |
| `--no-deps` | false | lewati pemindaian dependency & CVE (offline) |
| `--sbom-out` | – | tulis SBOM (SPDX 2.3 JSON) ke file |
| `--adapter` | semua | adapter eksternal: `bandit` \| `semgrep` \| `pip-audit` (bisa diulang) |
| `--adapter-sandbox` | `default` | sandbox adapter: `none` \| `default` \| `strict` |
| `--no-adapters` | false | lewati adapter eksternal |

### Exit codes

| Code | Arti |
| --- | --- |
| `0` | scan sukses, tidak ada temuan ≥ `--fail-on` |
| `1` | ada temuan ≥ `--fail-on` |
| `2` | error scan (path/remote tidak valid, dst.) |

## Rules bawaan

| Rule | Severity | Bahasa | Deteksi |
| --- | --- | --- | --- |
| `GO-TEMP-001` | high | Go | `ioutil.TempFile` / `os.CreateTemp("", …)` (AST) |
| `PY-DESER-001` | high | Python | `yaml.load` tanpa SafeLoader / `pickle` / `marshal` (AST) |
| `SECRET-001` | high | multi | hardcoded secret (kata kunci, AWS/Google/Slack/GitHub/Stripe/JWT) |
| `SECRET-002` | critical | multi | kunci privat ter-commit (PEM) |
| `TODO-001` | info | multi | penanda TODO/FIXME/HACK/XXX |
| `DBG-001` | low | js/py | `console.log` / `print` / debug sisa |
| `GIT-001` | critical | – | file sensitif ter-commit (`.env`, `id_rsa`, `*.pem`, …) |
| `GIT-002` | low | – | file besar ter-track |
| `GIT-003`–`GIT-005` | info | – | README / LICENSE / `.gitignore` tidak ada |
| `GIT-006` | info | – | churn hotspot (file sering berubah) |
| `SEC-INJ-001` | high | multi | command/SQL/eval injection |
| `SEC-PERM-001` | high | multi | permission world-writable (0777) |
| `SEC-CRYPTO-001` | medium | multi | hash lemah (MD5/SHA1) |
| `SEC-DISC-001` | medium | multi | info disclosure (debug/stack trace) |
| `SEC-LOG-001` | low | multi | log injection |
| `SEC-RACE-001` | medium | go/py | TOCTOU (check-then-use) |
| `POSTURE-001`–`005` | low–high | Docker | base `:latest`, user root, `curl\|sh`, secret di ENV/ARG |
| `POSTURE-006`–`008` | medium–high | compose | privileged, host namespace, mount `docker.sock` |
| `POSTURE-010`–`014` | low–high | K8s | privileged, host namespace/hostPath, `runAsUser: 0`, `:latest` |
| `POSTURE-020`–`023` | low–high | Actions | `pull_request_target`, script injection, `write-all`, action tak di-pin SHA |
| `DUP-001` | low | go/py/js/… | blok kode duplikat (token-window) |
| `TAINT-001` | high | multi | input (HTTP/CLI) mengalir ke sink (exec/SQL/log) |
| `DEP-001` | low–critical | – | dependency rentan (CVE via OSV) |
| `DEP-002` / `DEP-003` | low | – | lockfile tidak ada / dependency tidak di-pin |
| `ADP-*` | variatif | multi | temuan dari adapter (`bandit`/`semgrep`/`pip-audit`) |

### Supply chain

```sh
# SBOM (SPDX 2.3) + CVE OSV
issue-detector scan . --sbom-out sbom.spdx.json

# Adapter eksternal (dijalankan ter-sandbox; di-skip bila tool absen)
issue-detector scan . --adapter semgrep --adapter-sandbox default

# Laporan HTML self-contained
issue-detector scan . -f html -o report.html
```

### Baseline (CI)

Tandai temuan lama agar CI hanya gagal pada isu **baru**:

```sh
issue-detector baseline . -o .issue-detector-baseline.json   # sekali
issue-detector scan . --baseline .issue-detector-baseline.json --fail-on high
```

### Rule kustom (YAML)

Taruh file `*.yaml` di `.issue-detector/rules/` atau oper via `--rules <path>`:

```yaml
id: ACME-001
category: quality
severity: medium
title: fmt.Println terdeteksi
message: Gunakan logger, bukan fmt.Println.
fix_hint: ganti dengan slog.
languages: [go]
match:
  kind: regex          # atau: ast (tree-sitter query)
  pattern: '\bfmt\.Println\('
```

## Output contoh

```json
{
  "schema_version": "1",
  "tool": {"name": "issue-detector", "version": "0.1.0-dev"},
  "scan_id": "5f3c…",
  "summary": {"files_enumerated": 33, "files_parsed": 33, "files_skipped": 0, "files_errors": 0, "findings": 14, "by_severity": {"critical": 3, "high": 8, "low": 1, "info": 2}},
  "findings": [ { "rule": "SECRET-001", "severity": "critical", "source": "rule", "file": "…", "line": 7, "message": "…", "confidence": 0.99, "fix": "…" } ]
}
```

## Roadmap

- **M5** — AI-assisted (Mode B): provider OpenAI-compatible/Gemini, enrichment, redaksi secret
- **M7** — `watch` live-reload & trending
- **M8** — Web UI (rdr-httpman)
- **M10** — MCP `issue-detector` + loop agent-fix (lih. PRD §3.7)

## Development

```sh
go build ./...
go vet ./...
go test ./...          # bisa + -race
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Smoke test cepat di fixture:

```sh
go run ./cmd/issue-detector scan internal/testdata/sample --quiet
```

## License

[MIT](LICENSE) — © 2026 Muhammad Abdurrahman