package commands

import "github.com/spf13/cobra"

func XipherCommand() *cobra.Command {
	if xipherCmd != nil {
		return xipherCmd
	}
	xipherCmd = &cobra.Command{
		Use:   appName,
		Short: "Xipher is a curated collection of cryptographic primitives put together to perform password-based asymmetric encryption. It is written in Go and can be used as a library or a CLI tool.",
		Run: func(cmd *cobra.Command, args []string) {
			version, _ := cmd.Flags().GetBool(versionFlag.name)
			if version {
				showVersionInfo()
			} else {
				cmd.Help()
			}
		},
	}
	xipherCmd.Flags().BoolP(versionFlag.name, versionFlag.shorthand, false, versionFlag.usage)
	xipherCmd.AddCommand(versionCommand())
	xipherCmd.AddCommand(keygenCommand())
	xipherCmd.AddCommand(encryptCommand())
	xipherCmd.AddCommand(decryptCommand())
	return xipherCmd
}
