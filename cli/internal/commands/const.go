package commands

import "github.com/spf13/cobra"

const (
	appName = "xipher"
)

var (
	// Xipher Command
	xipherCmd *cobra.Command

	// Version Command
	versionCmd *cobra.Command
)

type flagDef struct {
	name      string
	shorthand string
	usage     string
}

var (
	// Common Flags

	versionFlag = flagDef{
		name:      "version",
		shorthand: "v",
		usage:     "Shows version info",
	}
)
