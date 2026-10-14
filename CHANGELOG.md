# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/). Versi mengikuti
SemVer. `schema_version` laporan JSON = kontrak output (lihat `internal/version`).

## [Unreleased]

### Changed
- Migrasi dependency worker/queue dari `github.com/rachmanzz/fiber-extras/v3/*`
  ke **`github.com/rachmanzz/gosuite/v3/{worker,queue}` v0.2.3** (monorepo
  multi-modul pengganti; package framework-agnostic). v0.2.3 membuat
  `subWorkerPool.Wait()` idempoten (`sync.Once`), menghilangkan galat palsu
  `context canceled` yang memicu retry + DLQ pada scan queue.
- Scanner: queue kini **proses-level, didaftarkan sekali**. Handler tunggal
  `handleScanFile` (didaftarkan tepat sekali di router yang dibuat lewat
  `getQueue`) **tidak terikat** ke scan mana pun — ia resolve `*Scanner` dari
  `scanID` di payload (`scanStates sync.Map`). `Scan()` hanya **dispatch** lalu
  menunggu settle; consumer bersama yang men-trigger handler. Tidak ada
  `RegisterHandler` berulang, tak ada `SetDriver`/`StartConsumer` global, dan
  tak ada serialisasi — beberapa scan paralel aman (mis. `serve`).
- AI-only (AI-detector): format respons default kini **`block`** — blok teks
  baris-per-baris (`[finding]` + `line=`/`severity=`/`category=`/`conf=`/
  `title=`/`message=`/`fix=`) — lebih tahan terhadap keluaran model yang
  terpotong: temuan yang sudah lengkap tetap terbaca walau ekor balasan rusak
  (JSON ter-truncate membuang seluruh balasan). Parser tetap menerima JSON
  sebagai fallback; `PromptVersion` dinaikkan sehingga cache lama tidak dipakai.

### Added
- CI `test` workflow: `gofmt`/`build`/`vet`/`go test -race` + artifact coverage.
- Endpoint probe `GET /healthz` dan `GET /readyz` pada `serve` (tanpa token).
- Golden test untuk kontrak report JSON & SARIF (`internal/report/testdata`).
- Fuzz target: `internal/parser`, `internal/delta`, `internal/pack`.
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `Dockerfile`.
- Flag `--no-ai`: matikan AI (menang atas `--ai` dan `ai.enabled` dari config
  project/global), untuk memaksa scan rule-only.
- Flag `--since N`: re-scan perubahan `N` commit terakhir (basis `HEAD~N`,
  otomatis abaikan cache) — bentuk ringkas dari `--base HEAD~N --force`, mis.
  untuk memaksa scan AI-only mundur lebih jauh dari commit terakhir yang dicek.
- AI-only: format respons detektor dapat dipilih lewat flag `--ai-format`
  (`block`|`json`) atau config `ai.format`.
- Supply chain: semua GitHub Action di-pin ke commit SHA (`supply-chain.yml`
  mem-verifikasi ini di CI); workflow `release.yml` membuat binary multi-OS,
  SBOM, checksum, dan **build provenance bertanda-tangan** (keyless).

### Fixed
- `score`: hilangkan state global (`SetDefaults`) → scoring aman untuk scan
  konkuren (`serve`); bobot dipass per panggilan.
- CLI: error yang dikembalikan kini dicetak (sebelumnya ditelan `SilenceErrors`).
- `fetcher`: hormati negasi `.gitignore` (`!`) dan `.gitignore` bersarang; trim CRLF.
- `sign`/`pack`: keyring rusak gagal keras (tak lagi panic `ed25519`); tolak pack
  ber-`.sig` tanpa keyring; bersihkan dir temp pack.
- `ai`: respons model yang gagal parse diperlakukan sebagai error (tidak di-cache,
  scan ditandai `partial`); hormati `confidence` 0; cache key per lokasi temuan;
  cache AI dibatasi.
- `cache`: path state AI/sesi relatif di-anchor ke `~/.issues_detector`
  (tidak lagi ditulis ke repo yang dipindai).
- Self-scan baseline dipulihkan (CI self-scan hijau kembali).
- `rules`: matcher pola-kode (`SEC-INJ/PERM/CRYPTO/DISC/LOG`, TOCTOU, `DBG`)
  kini mengabaikan baris komentar, sehingga rule tidak lagi cocok dengan contoh
  di komentarnya sendiri; pola pprof `SEC-DISC` mewajibkan kutip agar tidak
  cocok dengan literal raw-string milik rule sendiri.
- `posture`: `POSTURE-002` tidak lagi dilaporkan bila base image sudah non-root
  (distroless `:nonroot` / `-unprivileged`).
- `posture`: `FROM --platform=…` tidak lagi salah dibaca sebagai referensi image
  (mis. `FROM --platform=$BUILDPLATFORM golang:1.22 AS build` tak lagi memicu
  `POSTURE-001` palsu; base non-root di belakang `--platform` juga dikenali).
- `posture`: manifest YAML multi-dokumen (`---`, umum pada Kubernetes) kini
  seluruhnya dipindai — sebelumnya hanya dokumen pertama (`yaml.Unmarshal`).
- `posture`: ekspansi alias/anchor YAML dibatasi (tiap target alias dikunjungi
  sekali) untuk mencegah DoS "billion laughs" dan rekursi tak berujung.
- `scanner`: perbaiki race yang bisa menjatuhkan temuan — commit agregasi kini
  dilakukan **sebelum** tracker menandai selesai, sehingga `Scan()` tidak lagi
  snapshot sebelum temuan file terakhir masuk (temuan seharusnya deterministik).
- Self-scan repo ini (test di-skip): temuan 63 → 14, dua rule self-match dan
  false positive Dockerfile hilang.
