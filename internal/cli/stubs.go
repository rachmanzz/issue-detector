package cli

import (
	"fmt"
	"os"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/spf13/cobra"
)

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

jobs: 0                 # worker; 0 = NumCPU
sub_worker: 5           # fan-out sub-worker per file
max_file_size: 1048576  # batas ukuran file (1 MiB)
timeout: 0s             # batas durasi scan (0 = tak terbatas)
fail_on: none           # none|low|medium|high|critical
severity_min: ""        # minimum severity dilaporkan
categories: []          # kategori aktif (kosong = semua)
ignore: []              # pola ignore tambahan (globs)
remote: ""              # git URL untuk clone
base: ""                # delta scan: ref git
diff: ""                # delta scan: file patch
no_git: false           # lewati analisis git
rules: []               # rule YAML eksternal
rules_dir: .issue-detector/rules

# AI enrichment (Mode B) — nonaktif secara default
ai:
  enabled: false
  provider: openai      # openai | gemini
  model: ""             # default per provider
  base_url: ""          # override (Ollama/vLLM/Azure)
  api_key_env: ""       # nama env var key (default OPENAI_API_KEY/GEMINI_API_KEY)
  max_findings: 25
  budget_tokens: 100000
  cache_dir: .issue-detector-cache
`
	if err := os.WriteFile(config.FileName, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Printf("dibuat %s\n", config.FileName)
	return nil
}
