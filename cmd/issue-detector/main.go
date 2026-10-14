package main

import (
	"fmt"
	"os"

	"github.com/rachmanzz/issue-detector/internal/cli"
)

func main() {
	// Execute handles gate exit codes itself (ExitError); anything returned here
	// is a real error that was previously swallowed by SilenceErrors, so print it.
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
