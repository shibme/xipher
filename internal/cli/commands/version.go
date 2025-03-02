package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"xipher.org/xipher"
)

func showVersionInfo(jsonFormat bool) {
	if jsonFormat {
		fmt.Println(toJsonString(xipher.Info))
	} else {
		var committedAt string
		if builtAtTime, err := time.Parse(time.RFC3339, xipher.Info.BuiltAt); err == nil {
			builtAtLocalTime := builtAtTime.Local()
			committedAt = builtAtLocalTime.Format("02 Jan 2006 03:04:05 PM MST")
		}
		appInfoBuilder := strings.Builder{}
		appInfoBuilder.WriteString(xipher.Info.Art)
		appInfoBuilder.WriteString("\n")
		appInfoBuilder.WriteString(xipher.Info.Description)
		appInfoBuilder.WriteString("\n")
		appInfoBuilder.WriteString("-------------------------------------------------")
		appInfoBuilder.WriteString("\n")
		appInfoBuilder.WriteString(fmt.Sprintf("Version    : %s\n", xipher.Info.Version))
		appInfoBuilder.WriteString(fmt.Sprintf("Built At   : %s\n", committedAt))
		appInfoBuilder.WriteString(fmt.Sprintf("Release    : %s\n", xipher.Info.ReleaseURL))
		appInfoBuilder.WriteString(fmt.Sprintf("Git Commit : %s\n", xipher.Info.FullCommit))
		appInfoBuilder.WriteString(fmt.Sprintf("Web        : %s\n", xipher.Info.Web))
		appInfoBuilder.WriteString(fmt.Sprintf("Platform   : %s\n", xipher.Info.Platform))
		appInfoBuilder.WriteString(fmt.Sprintf("Go Version : %s", xipher.Info.GoVersion))
		fmt.Println(appInfoBuilder.String())
	}
}

func versionCommand() *cobra.Command {
	if versionCmd == nil {
		versionCmd = &cobra.Command{
			Use:   "version",
			Short: "Show version information",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				showVersionInfo(jsonFormat)
			},
		}
	}
	return versionCmd
}
