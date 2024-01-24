package main

import (
	"os"

	"dev.shib.me/xipher/cli/internal/commands"
)

func main() {
	if err := commands.XipherCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
