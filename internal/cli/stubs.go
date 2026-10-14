package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/spf13/cobra"
)

// writeGlobalCacheMode sets cache.mode in the per-user config while preserving
// any other keys. Used by `--install-temporary`.
func writeGlobalCacheMode(mode string) error {
	path, err := config.GlobalConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	m := map[string]any{}
	if b, rerr := os.ReadFile(path); rerr == nil && len(strings.TrimSpace(string(b))) > 0 {
		if err := yaml.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("config global rusak: %w", err)
		}
	}
	cm, _ := m["cache"].(map[string]any)
	if cm == nil {
		cm = map[string]any{}
	}
	cm["mode"] = mode
	m["cache"] = cm
	out, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// notYet returns a friendly error for commands reserved for later milestones.
func notYet(milestone, desc string) error {
	return fmt.Errorf("%s belum diimplementasikan (M0); masuk roadmap %s. PRD cek §3.7/§3.6/§11", desc, milestone)
}

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Buat config default issue-detector.yaml",
		RunE: func(_ *cobra.Command, _ []string) error {
			return writeDefaultConfig()
		},
	}
}

// writeDefaultConfig generates a commented issue-detector.yaml.
func writeDefaultConfig() error {
	content := `# issue-detector konfigurasi (PRD §6/§7)
# Nilai default ditampilkan; hapus baris untuk memakai bawaan.
# Alternatif: issue-detector.json (skema sama, format JSON) di root yang di-scan.

jobs: 0                 # worker; 0 = NumCPU
sub_worker: 5           # fan-out sub-worker per file
max_file_size: 1048576  # batas ukuran file (1 MiB)
timeout: 0s             # batas durasi scan (0 = tak terbatas)
fail_on: none           # none|low|medium|high|critical
severity_min: ""        # minimum severity dilaporkan
categories: []          # kategori aktif (kosong = semua)
ignore: []              # pola ignore tambahan (globs), mis. ["**/*_test.go"]
skip: []                # alias untuk ignore (file/pola yang di-skip)
remote: ""              # git URL untuk clone
base: ""                # delta scan: ref git
diff: ""                # delta scan: file patch
no_git: false           # lewati analisis git
rules: []               # rule YAML eksternal
rules_dir: .issue-detector/rules

# AI enrichment (Mode B) — default mengikuti config per-user.
# SENGAJA dikomentari: nilai kosong/false di config project akan menimpa
# (clobber) config per-user ~/.issues_detector/issue-detector.yaml. Biarkan
# terkomentari agar provider/model/base_url/enabled mewarisi per-user; buka
# komentar hanya bila ingin menimpa AI khusus project ini.
#
# ai:
#   enabled: true
#   provider: openai      # openai = protokol OpenAI-compatible (Ollama/vLLM/…)
#   model: ""             # default per provider; WAJIB bila base_url diisi
#   base_url: ""          # server OpenAI-compatible apa pun (key opsional utk lokal)
#   api_key_env: ""       # env var key (default OPENAI_API_KEY/GEMINI_API_KEY)
#   max_findings: 25
#   budget_tokens: 100000
#   only: false           # true = AI-detector (--ai-only)
#   max_files: 200        # batas file dikirim ke AI saat --ai-only
#   # cache_dir: (default: ~/.issues_detector/ai-cache)

# Session/change cache (PRD §10) — semua state tool ada di ~/.issues_detector
cache:
  enabled: true
  mode: global            # auto|global = ~/.issues_detector/cache; local = di samping executable
  # path: ""              # path kustom (menimpa mode)
  max_items: 50           # retensi LRU per sesi (0 = default 50)
`
	if err := os.WriteFile(config.FileName, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Printf("dibuat %s\n", config.FileName)
	return nil
}
