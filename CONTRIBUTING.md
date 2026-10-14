# Contributing

Terima kasih ingin berkontribusi. Singkat dan langsung:

## Sebelum mengirim perubahan

Jalankan persis apa yang dijalankan CI (`.github/workflows/test.yml`):

```sh
gofmt -l ./cmd ./internal      # harus kosong
go build ./...
go vet ./...
go test -race ./...
```

Perbaikan bug **wajib** disertai test yang gagal tanpa fix (lihat pola di repo:
test ditulis lebih dulu, lalu diperlihatkan gagal, lalu lulus).

## Konvensi

- Bahasa: kode & komentar teknis boleh Inggris; pesan commit mengikuti gaya repo
  (`area: ringkasan`, mis. `fetcher: ...`, `ai: ...`).
- Tanpa komentar kosmetik; jelaskan *kenapa*, bukan *apa*.
- Jangan menambah dependency baru bila stdlib cukup.
- Perilaku yang disengaja dibatasi ditandai eksplisit (komentar `CEILING`/PRD).

## Menjalankan

```sh
go run ./cmd/issue-detector scan . --no-deps --no-adapters
```

Mode AI (opt-in) butuh key via env, mis. `OPENAI_API_KEY` / `GEMINI_API_KEY`.

## Audit internal

Repo memelihara catatan audit di `.knowledges/roasted/` (lokal, gitignored)
sesuai `roasting_term.md`. Temuan ditandai `BUG`/`CEILING`/`PROSES` dan setiap
klaim harus punya rujukan `file:line`.
