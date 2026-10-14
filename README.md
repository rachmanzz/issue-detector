# issue-detector

Detektor masalah kode untuk project kecil–menengah. Men-scan folder lokal atau repo remote (clone shallow), mendeteksi temuan berbasis baris, dan melaporkannya dalam format `text` atau `json`. Didesain agar mudah di-"dogfood" oleh tool AI sebagai loop *agent → review → fix*.

## Fitur

- **Fetcher**: scan folder lokal, atau repo git remote via clone shallow (`go-git`); hormati `.gitignore`/`.issue-detectorignore` dan direktori umum yang di-ignore (`node_modules`, `vendor`, dll.).
- **Pipeline paralel**: tiap file diproses sebagai task pada in-memory queue; eksekusi oleh worker engine, dengan fan-out per rule (sub-worker) dan priorititas (secret-like files lebih dulu). Render-an akhir aggregator bersifat deterministik (sort severity → file → line) dan idempoten vs retry queue.
- **Rules**: registry + matcher line-based & AST (tree-sitter: Go/Python/JavaScript), plus rule kustom YAML.
- **Config**: nilai bawaan, file `issue-detector.yaml` (atau `.yml`/`.json`), dan override via flag CLI (flag hanya menimpa bila eksplisit di-set).
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
issue-detector watch [path] [flags]
issue-detector trend [flags]
issue-detector serve [flags]
issue-detector mcp [flags]              # MCP stdio untuk AI agent
issue-detector init                     # buat config default
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
| `--format` | `text` | `text` \| `json` \| `json-lines` \| `sarif` \| `html` |
| `--output` | stdout | tulis ke file, `-` = stdout |
| `--remote` | – | URL remote untuk clone & scan |
| `--categories` | semua | filter kategori temuan |
| `--severity-min` | `info` | ambang minimal severity |
| `--fail-on` | `none` | exit code 1 jika ada severity ≥ ambang |
| `--ai-gate` | `false` | ikutkan temuan AI (`source: ai`) ke gate `--fail-on` (default: advisory) |
| `--config` | `issue-detector.yaml` | path config YAML (`.yml` juga auto-detect) |
| `--jobs` | `NumCPU` | worker paralel |
| `--sub-worker-limit` | 0 (`5`) | fan-out sub-worker per file |
| `--max-file-size` | 0 (`1 MiB`) | batas ukuran file (bytes) |
| `--timeout` | 0 | batas durasi scan (detik, 0 = tanpa batas) |
| `--quiet` | false | hanya temuan (tanpa log engine) |
| `--ignore` | – | pola ignore tambahan (bisa diulang) |
| `--base` | – | delta scan: hanya baris berubah sejak ref git |
| `--since` | – | re-scan perubahan `N` commit terakhir (basis `HEAD~N`; abaikan cache) |
| `--diff` | – | delta scan: dari file patch (`.diff`/`.patch`) |
| `--force` | false | paksa scan ulang: abaikan hasil cache (tetap refresh cache) |
| `--no-cache` | false | jangan baca/tulis cache sesi (untuk CI paranoid) |
| `--no-git` | false | lewati analisis kesehatan git |
| `--rules` | `--` | file/direktori rule YAML tambahan (bisa diulang) |
| `--baseline` | – | abaikan temuan yang sudah ada di file baseline |
| `--no-deps` | false | lewati pemindaian dependency & CVE (offline) |
| `--sbom-out` | – | tulis SBOM (SPDX 2.3 JSON) ke file |
| `--adapter` | semua | adapter eksternal: `bandit` \| `semgrep` \| `pip-audit` (bisa diulang) |
| `--adapter-sandbox` | `default` | sandbox adapter: `none` \| `default` \| `strict` |
| `--no-adapters` | false | lewati adapter eksternal |
| `--ai` | false | aktifkan AI enrichment (Mode B); butuh API key env |
| `--ai-only` | false | mode AI-detector: AI cari isu sendiri, rule engine dilewati |
| `--no-ai` | false | matikan AI (menang atas `--ai` dan `ai.enabled` config) |
| `--ai-provider` | `openai` | provider AI: `openai` \| `gemini` |
| `--ai-model` | – | nama model (default per provider) |
| `--ai-max-findings` | 25 | maksimum temuan di-enrich |
| `--ai-budget-tokens` | 100000 | budget token AI (perkiraan) |
| `--ai-format` | `block` | format balasan AI-only: `block` (key=value, tahan output terpotong) \| `json` |
| `--plugin` | – | plugin WASM (.wasm file/direktori; bisa diulang) |
| `--pack` | – | rule pack (direktori atau `.tar.gz`; bisa diulang) |
| `--require-signature` | false | wajibkan tanda tangan valid untuk pack |
| `--pack-keyring` | – | keyring ed25519 (baris base64 public key) |
| `--web` | false | jalankan Mode Web interaktif setelah scan |
| `--web-port` | 8088 | port Mode Web |
| `--history` | – | simpan snapshot ke database history SQLite |

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

# AI enrichment (Mode B): penjelasan + saran perbaikan (temuan high/critical)
OPENAI_API_KEY=... issue-detector scan . --ai --ai-provider openai --ai-model gpt-4o-mini
```

### AI (Mode B)

Enrichment hanya untuk temuan **high/critical**; temuan AI (`source: ai`) secara default **advisory** (dikecualikan dari `--fail-on`) — pakai `--ai-gate` untuk mengikutkannya ke gate, dan secret diredaksi sebelum dikirim. Konfigurasi bisa lewat flag CLI atau `issue-detector.yaml` (flag menimpa YAML):

```yaml
ai:
  enabled: true
  provider: openai        # "openai" = protokol OpenAI-compatible (bukan hanya api.openai.com)
  model: gpt-4o-mini      # default per provider; WAJIB bila base_url diisi
  base_url: ""            # server OpenAI-compatible apa pun
  api_key: ""             # literal key (opsional) — JANGAN commit; file config sudah gitignored
  api_key_env: ""         # alternatif: nama env var (default OPENAI_API_KEY / GEMINI_API_KEY)
  max_findings: 25
  budget_tokens: 100000
  cache_dir: .issue-detector-cache
  format: block           # format respons AI-only: "block" (default, tahan truncate) | "json"
```

> Urutan resolusi key: `api_key` (literal) → `api_key_env` (nama env) → `OPENAI_API_KEY`/`GEMINI_API_KEY`. `issue-detector.yaml`/`.yml`/`.json` sudah masuk `.gitignore` — jangan pernah commit key.

`provider: openai` berarti **protokol OpenAI-compatible** — cocok untuk Ollama, vLLM, LM Studio, llama.cpp, OpenRouter, Azure, dsb. `base_url` mengarah ke server mana pun; **tidak harus dari OpenAI**. Bila `base_url` diisi, `model` wajib disebut, dan **API key opsional** (server lokal biasanya tanpa key):

```sh
# Ollama (lokal, tanpa key)
issue-detector scan . --ai --ai-base-url http://localhost:11434/v1 --ai-model llama3

# vLLM / LM Studio
issue-detector scan . --ai --ai-base-url http://localhost:8000/v1 --ai-model mistral-7b

# OpenRouter (butuh key)
OPENAI_API_KEY=sk-or-... issue-detector scan . \
  --ai --ai-base-url https://openrouter.ai/api/v1 --ai-model openai/gpt-4o-mini
```

Verifikasi koneksi AI tanpa scan penuh (kirim 1 prompt, tampilkan balasannya):

```sh
issue-detector ai test --root .              # pakai issue-detector.yaml
issue-detector ai test --provider openai --base-url http://localhost:11434/v1 --model llama3
```

Saat `ai.enabled: true`, `scan` mencetak diagnostik ke stderr: `config dimuat … ai_enabled`, `AI enrichment kandidat_high_critical=N`, dan `enriched=N` — atau `ERROR AI enrichment gagal (endpoint/key?)` bila endpoint tak terjangkau (tetap tampil walau `--quiet`).

### Scan incremental (AI)

Saat scan AI dijalankan (`--ai-only` atau `ai.enabled: true`), cache sesi mencatat commit terakhir yang dicek, sehingga scan berikutnya **hanya memeriksa perubahan** — temuan lama tidak dipindai ulang. Untuk memaksa periksa ulang mundur beberapa commit:

```sh
# hanya perubahan sejak scan terakhir
issue-detector scan . --ai-only

# paksa periksa ulang sejak 3 commit ke belakang
issue-detector scan . --ai-only --since 3

# ekuivalen eksplisit (--since = --base HEAD~N + --force)
issue-detector scan . --ai-only --base HEAD~3 --force
```

Format respons detektor default **`block`** — blok teks `key=value` (`[finding]` + `line=`/`severity=`/`category=`/`conf=`/`title=`/`message=`/`fix=`) yang lebih tahan terhadap keluaran AI yang terpotong: temuan yang sudah lengkap tetap terbaca walau ekor respons rusak (JSON ter-truncate membuang seluruh balasan). Parser tetap menerima JSON sebagai fallback. Pilih eksplisit dengan `--ai-format json` atau `ai.format: json`.

### Plugin WASM

```sh
issue-detector scan . --plugin plugins/ --pack custom-rules.tar.gz \
  --require-signature --pack-keyring keys.txt
```

Plugin adalah modul WASI command (Go: `GOOS=wasip1 GOARCH=wasm`). Host menjalankannya via [wazero](https://wazero.io) dengan root scan di-mount **read-only**, arg `[name, "/"]`, dan membaca array JSON temuan dari stdout `model.Finding` (field `source` default `plugin`):

```go
//go:build wasip1
package main

import ("encoding/json"; "os")

func main() {
    findings := []map[string]any{{"rule_id": "MY-001", "severity": "high", "file": "a.go", "line": 10, "message": "…"}}
    _ = json.NewEncoder(os.Stdout).Encode(findings)
}
```

Rule pack = direktori `*.yaml` atau bundel `.tar.gz`; pakai `--pack` dan (opsional) verifikasi ed25519 via `--require-signature --pack-keyring keys.txt` (tanda tangan di `<pack>.sig`).

### Baseline (CI)

Tandai temuan lama agar CI hanya gagal pada isu **baru**:

```sh
issue-detector baseline . -o .issue-detector-baseline.json   # sekali
issue-detector scan . --baseline .issue-detector-baseline.json --fail-on high
```

### Watch & trend (history)

Setiap temuan diberi `priority_score` (0–100) + `score_reason` yang bisa diaudit. Simpan snapshot ke SQLite lalu lihat tren:

```sh
issue-detector watch . --history .issue-detector-history.db --interval 1m
issue-detector trend --history .issue-detector-history.db
issue-detector scan . --history .issue-detector-history.db   # snapshot tunggal
```

### Mode Web (PRD §3.6)

UI interaktif embedded (Fiber v3) — hidupkan dengan `serve` (long-running) atau `scan --web`:

```sh
issue-detector serve --root . --history .issue-detector-history.db
issue-detector scan . --web
```

Endpoint: `GET /` (UI), `GET /api/scan` (hasil + filter `severity_min`/`category`/`source`/`in_diff`), `GET /api/events` (SSE live progress), `GET /api/rules`, `GET /api/trend`, `POST /api/triage` (mark FP → baseline), `POST /api/rules/test` (rule lab). Sekuriti: bind default `127.0.0.1`, guard Origin anti-CSRF, header CSP ketat (script eksternal), dan **`--ui-token`** — wajib untuk bind di luar localhost serta untuk semua `/api/*` dan `/mcp` bila di-set. Tanpa autentikasi di loopback; jangan bind ke jaringan tanpa `--ui-token`.

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

- **Selesai (M0–M10)** — lihat `.knowledges/phases.md` untuk status rinci mileston; fitur lanjutan (dataflow graf UI, AI Q&A, transport SSE MCP, CD rilis) tercatat sebagai *ceiling* di sana.

### Agent / MCP (PRD §3.7)

MCP server JSON-RPC 2.0 dengan 6 tools (`scan`, `get_finding`, `fix_hint`, `rules_list`, `baseline_ignore`, `trend`):

```sh
issue-detector mcp --root .                     # transport stdio (Claude Code / opencode)
issue-detector serve --mcp --port 8088          # transport http: POST http://127.0.0.1:8088/mcp
issue-detector scan . -f json-lines             # satu temuan JSON per baris
```

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