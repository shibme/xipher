package commands

import (
	"fmt"
	"os"
	"strings"

	"dev.shib.me/xipher/utils"
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
			autoGen, _ := cmd.Flags().GetBool(autoGenerateSecretKey.name)
			quantumSafe, _ := cmd.Flags().GetBool(quantumSafeFlag.name)
			var secret string
			var err error
			if autoGen {
				if secret, err = utils.NewSecretKey(); err != nil {
					exitOnError(err)
				}
				fmt.Println("Secret Key:", color.HiBlackString(secret))
			} else {
				password, err := getPasswordFromUser(true, ignoreFlag)
				if err != nil {
					exitOnError(err)
				}
				secret = string(password)
			}
			pubKeyStr, err := utils.GetPublicKey(secret, quantumSafe)
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
	keygenCmd.Flags().BoolP(ignorePasswordCheckFlag.flagFields())
	keygenCmd.Flags().StringP(publicKeyFileFlag.flagFields())
	keygenCmd.Flags().BoolP(autoGenerateSecretKey.flagFields())
	keygenCmd.Flags().BoolP(quantumSafeFlag.flagFields())
	return keygenCmd
}
