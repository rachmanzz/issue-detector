package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/ai"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/spf13/cobra"
)

// newAICmd provides `ai test` to verify AI provider wiring.
func newAICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "Utilitas AI (Mode B)",
	}
	cmd.AddCommand(newAITestCmd())
	return cmd
}

func newAITestCmd() *cobra.Command {
	var (
		cfgPath  string
		root     string
		provider string
		model    string
		baseURL  string
		keyEnv   string
	)
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Uji koneksi AI (kirim satu prompt) dan tampilkan hasilnya",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()
			if cfgPath == "" {
				for _, name := range []string{config.FileName, "issue-detector.yml"} {
					p := root + string(os.PathSeparator) + name
					if _, err := os.Stat(p); err == nil {
						cfgPath = p
						break
					}
				}
			}
			if cfgPath != "" {
				loaded, err := config.Load(cfgPath, true)
				if err != nil {
					return fmt.Errorf("config: %w", err)
				}
				cfg = loaded
				fmt.Fprintf(os.Stderr, "config: %s\n", cfgPath)
			} else {
				fmt.Fprintln(os.Stderr, "config: tidak ada (pakai flag/env)")
			}

			ac := cfg.AI
			if provider != "" {
				ac.Provider = provider
			}
			if model != "" {
				ac.Model = model
			}
			if baseURL != "" {
				ac.BaseURL = baseURL
			}
			if keyEnv != "" {
				ac.APIKeyEnv = keyEnv
			}
			prov := ac.Provider
			if prov == "" {
				prov = "openai"
			}
			key := aiAPIKey(ac, prov)
			fmt.Fprintf(os.Stderr, "provider=%s model=%q base_url=%q key_env=%q key=%s\n",
				prov, ac.Model, ac.BaseURL, ac.APIKeyEnv, maskKey(key))

			reply, err := ai.Probe(cmd.Context(), ai.Config{
				Provider: prov, Model: ac.Model, BaseURL: ac.BaseURL, APIKey: key,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "GAGAL:", err)
				return exit(2)
			}
			fmt.Println(strings.TrimSpace(reply))
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&cfgPath, "config", "", "path config YAML")
	fl.StringVar(&root, "root", ".", "root untuk cari config default")
	fl.StringVar(&provider, "provider", "", "openai|gemini")
	fl.StringVar(&model, "model", "", "nama model")
	fl.StringVar(&baseURL, "base-url", "", "base URL OpenAI-compatible")
	fl.StringVar(&keyEnv, "key-env", "", "nama env var API key")
	return cmd
}

func maskKey(k string) string {
	if k == "" {
		return "(kosong)"
	}
	if len(k) <= 6 {
		return "***"
	}
	return k[:3] + "***" + k[len(k)-2:]
}
