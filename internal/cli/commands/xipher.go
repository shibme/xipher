package commands

import (
	"github.com/spf13/cobra"
	"xipher.org/xipher"
)

func XipherCommand() *cobra.Command {
	if xipherCmd == nil {
		xipherCmd = &cobra.Command{
			Use:   appNameLowerCase,
			Short: xipher.Info.Description,
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				version, _ := cmd.Flags().GetBool(versionFlag.name)
				if version {
					showVersionInfo(jsonFormat)
				} else {
					cmd.Help()
				}
			},
		}
		xipherCmd.PersistentFlags().BoolP(jsonFlag.fields())
		xipherCmd.Flags().BoolP(versionFlag.fields())
		xipherCmd.AddCommand(versionCommand())
		xipherCmd.AddCommand(keygenCommand())
		xipherCmd.AddCommand(encryptCommand())
		xipherCmd.AddCommand(decryptCommand())
	}
	return xipherCmd
}
