package cli

import (
	"fmt"

	"github.com/rachmanzz/issue-detector/internal/rules"
	"github.com/spf13/cobra"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Kelola rule engine (builtin M0; YAML/WASM menyusul)",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "Daftar rule yang tersedia",
			RunE: func(_ *cobra.Command, _ []string) error {
				reg := rules.NewRegistry()
				for _, r := range reg.All() {
					langs := "all"
					if len(r.Languages) > 0 {
						langs = ""
						for i, l := range r.Languages {
							if i > 0 {
								langs += ","
							}
							langs += string(l)
						}
					}
					fmt.Printf("%-14s %-9s %-8s %-22s langs=%s\n",
						r.ID, r.Category, r.Severity, r.Title, langs)
				}
				return nil
			},
		},
	)
	return cmd
}
