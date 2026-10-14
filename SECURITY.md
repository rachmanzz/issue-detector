# Security Policy

## Supported versions

Hanya rilis terbaru di branch `main` yang didukung dengan perbaikan keamanan.

## Melaporkan kerentanan

Jangan buka issue publik untuk masalah keamanan. Kirim laporan privat ke
maintainer (lihat `go.mod`/profil repo) dengan:

- deskripsi dampak (mis. RCE/DoS/leak),
- langkah reproduksi atau PoC,
- versi/commit yang terpengaruh.

Kami berusaha membalas dalam 7 hari kerja dan akan memberi kredit bila diinginkan.

## Cakupan & model ancaman

- Tool ini memindai **input tidak tepercaya**: source code, repo remote, pack
  `.tar.gz`, plugin WASM. Titik masuk ini di-*fuzz* (`internal/{parser,delta,pack}`).
- Semua state tool hidup di `~/.issues_detector/`; **tidak ada yang ditulis ke
  repo yang dipindai** (PRD §7.1). Path relatif di-anchor ke dir per-user.
- Mode AI (opt-in) meredaksi pola secret sebelum mengirim dan mengecualikan
  temuan `source=ai` dari gate secara default.
- `serve` bind `127.0.0.1`; membuka ke jaringan butuh `--host` + `--ui-token`.
- Verifikasi rule-pack memakai ed25519; keyring yang tidak valid **gagal keras**
  (tidak ada kunci nil, tidak ada verifikasi senyap).

## Praktik dependency

CI menjalankan `govulncheck` dan `go test -race` pada setiap push/PR.
