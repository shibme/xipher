package main

import (
	"os"

	"dev.shib.me/xipher/internal/cli/commands"
)

func main() {
	if err := commands.XipherCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
