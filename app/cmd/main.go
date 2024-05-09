package main

import (
	"os"

	"dev.shib.me/xipher/app/internal/commands"
)

func main() {
	if err := commands.XipherCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
