package commands

import (
	"fmt"
	"os"
	"strings"

	"dev.shib.me/xipher/app/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func keygenCommand() *cobra.Command {
	if keygenCmd != nil {
		return keygenCmd
	}
	keygenCmd = &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new key pair or public key based on a password",
		Run: func(cmd *cobra.Command, args []string) {
			publicKeyFilePath := cmd.Flag(publicKeyFileFlag.name).Value.String()
			ignoreFlag, _ := cmd.Flags().GetBool(ignorePasswordCheckFlag.name)
			quantumSafe, _ := cmd.Flags().GetBool(quantumSafeFlag.name)
			password, err := getPasswordFromUser(true, ignoreFlag)
			if err != nil {
				exitOnError(err)
			}
			pubKeyStr, err := utils.GetPublicKey(string(password), quantumSafe)
			if err != nil {
				exitOnError(err)
			}
			if publicKeyFilePath != "" {
				if !strings.HasSuffix(publicKeyFilePath, xipherPubKeyFileExt) {
					publicKeyFilePath += xipherPubKeyFileExt
				}
				if err := os.WriteFile(publicKeyFilePath, []byte(pubKeyStr), 0600); err != nil {
					exitOnError(err)
				}
				fmt.Println("Public Key saved to:", color.GreenString(publicKeyFilePath))
			} else {
				fmt.Println("Public Key:", color.GreenString(pubKeyStr))
			}
			fmt.Println("It is completely safe to share this public key with anyone.")
		},
	}
	keygenCmd.Flags().BoolP(ignorePasswordCheckFlag.name, ignorePasswordCheckFlag.shorthand, false, ignorePasswordCheckFlag.usage)
	keygenCmd.Flags().StringP(publicKeyFileFlag.name, publicKeyFileFlag.shorthand, "", publicKeyFileFlag.usage)
	keygenCmd.Flags().BoolP(quantumSafeFlag.name, quantumSafeFlag.shorthand, false, quantumSafeFlag.usage)
	return keygenCmd
}
