# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/). Versi mengikuti
SemVer. `schema_version` laporan JSON = kontrak output (lihat `internal/version`).

## [Unreleased]

### Changed
- Migrasi dependency worker/queue dari `github.com/rachmanzz/fiber-extras/v3/*`
  ke **`github.com/rachmanzz/gosuite/v3/{worker,queue}` v0.2.2** (monorepo
  multi-modul pengganti; package framework-agnostic).
- Scanner: queue kini **proses-level, didaftarkan sekali**. Handler tunggal
  `handleScanFile` (didaftarkan tepat sekali di router yang dibuat lewat
  `getQueue`) **tidak terikat** ke scan mana pun — ia resolve `*Scanner` dari
  `scanID` di payload (`scanStates sync.Map`). `Scan()` hanya **dispatch** lalu
  menunggu settle; consumer bersama yang men-trigger handler. Tidak ada
  `RegisterHandler` berulang, tak ada `SetDriver`/`StartConsumer` global, dan
  tak ada serialisasi — beberapa scan paralel aman (mis. `serve`).

### Added
- CI `test` workflow: `gofmt`/`build`/`vet`/`go test -race` + artifact coverage.
- Endpoint probe `GET /healthz` dan `GET /readyz` pada `serve` (tanpa token).
- Golden test untuk kontrak report JSON & SARIF (`internal/report/testdata`).
- Fuzz target: `internal/parser`, `internal/delta`, `internal/pack`.
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `Dockerfile`.
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
