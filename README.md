# issue-detector

Detektor masalah kode untuk project kecil–menengah. Men-scan folder lokal atau repo remote (clone shallow), mendeteksi temuan berbasis baris, dan melaporkannya dalam format `text` atau `json`. Didesain agar mudah di-"dogfood" oleh tool AI sebagai loop *agent → review → fix*.

## Fitur

- **Fetcher**: scan folder lokal, atau repo git remote via clone shallow (`go-git`); hormati `.gitignore`/`.issue-detectorignore` dan direktori umum yang di-ignore (`node_modules`, `vendor`, dll.).
- **Pipeline paralel**: tiap file diproses sebagai task pada in-memory queue; eksekusi oleh worker engine, dengan fan-out per rule (sub-worker) dan priorititas (secret-like files lebih dulu). Render-an akhir aggregator bersifat deterministik (sort severity → file → line) dan idempoten vs retry queue.
- **Rules**: registry + matcher sederhana berbasis baris (parsing penuh menyusul, lihat Roadmap).
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
| `--format` | `text` | `text` \| `json` (`sarif` menyusul) |
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

### Exit codes

| Code | Arti |
| --- | --- |
| `0` | scan sukses, tidak ada temuan ≥ `--fail-on` |
| `1` | ada temuan ≥ `--fail-on` |
| `2` | error scan (path/remote tidak valid, dst.) |

## Rules bawaan (M0)

| Rule | Severity | Bahasa | Deteksi |
| --- | --- | --- | --- |
| `GO-TEMP-001` | high | Go | `ioutil.TempFile` deprecated/tidak aman |
| `SECRET-001` | critical | multi | hardcoded secret (kata kunci + nilai) |
| `SECRET-002` | critical | pem/ssh | kunci privat ter-commit (PEM/private) |
| `TODO-001` | info | multi | penanda TODO/FIXME |
| `DBG-001` | low | js/py/go | `console.log` / `print` / debug sisa |

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

- **M1** — parsing AST via tree-sitter (Go/JS/Python) menggantikan line-based
- **M2** — kategori/rule lebih luas (SQL-injection, XSS template, dsb.)
- **M3** — output SARIF + baseline ignore
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