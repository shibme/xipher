package main

import (
	"os"

	"xipher.org/xipher/internal/cli/commands"
)

func main() {
	if err := commands.XipherCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
