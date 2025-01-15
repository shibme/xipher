package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"xipher.org/xipher"
)

func showVersionInfo() {
	fmt.Println(xipher.VersionInfo())
}

func versionCommand() *cobra.Command {
	if versionCmd != nil {
		return versionCmd
	}
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			showVersionInfo()
		},
	}
	return versionCmd
}
