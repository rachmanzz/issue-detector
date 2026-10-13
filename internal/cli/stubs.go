package cli

import (
	"fmt"

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
			return fmt.Errorf("init belum diimplementasikan di M0")
		},
	}
}
