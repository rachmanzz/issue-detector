package main

import (
	"os"

	"github.com/rachmanzz/issue-detector/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
