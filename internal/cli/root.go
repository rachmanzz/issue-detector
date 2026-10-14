// Package cli wires the cobra command tree (PRD §7).
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/report"
	"github.com/rachmanzz/issue-detector/internal/version"
	"github.com/spf13/cobra"
)

// ExitError carries a process exit code out of command execution.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit code %d", e.Code) }

func exit(code int) error { return &ExitError{Code: code} }

// Execute runs the CLI; it os.Exit()s with the command's exit code.
func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := NewRootCmd()
	if err := root.ExecuteContext(ctx); err != nil {
		var ex *ExitError
		if errors.As(err, &ex) {
			os.Exit(ex.Code)
		}
		return err
	}
	return nil
}

// NewRootCmd builds the full command tree.
func NewRootCmd() *cobra.Command {
	var installTemporary bool

	root := &cobra.Command{
		Use:           "issue-detector",
		Short:         "Deteksi issue source code: security, quality, bugs, git health (PRD-driven)",
		SilenceUsage:  true,
		SilenceErrors: true,
		// RunE makes the bare root (e.g. `issue-detector --install-temporary`)
		// execute the persistent hook below; otherwise show help.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if !installTemporary {
				return nil
			}
			if err := writeGlobalCacheMode("global"); err != nil {
				return err
			}
			if p, err := config.GlobalConfigPath(); err == nil {
				fmt.Printf("cache mode=global diregister di %s\n", p)
			}
			return exit(report.ExitOK)
		},
	}

	root.PersistentFlags().BoolVar(&installTemporary, "install-temporary", false,
		"register mode cache global di ~/.issues_detector/issue-detector.yaml lalu keluar")

	root.AddCommand(
		newScanCmd(),
		newRulesCmd(),
		newVersionCmd(),
		newServeCmd(),
		newMCPCmd(),
		newWatchCmd(),
		newTrendCmd(),
		newBaselineCmd(),
		newAICmd(),
		newInitCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print versi tool",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("%s v%s\n", version.ToolName, version.Version)
			if version.Commit != "" {
				fmt.Printf("commit %s\n", version.Commit)
			}
		},
	}
}
