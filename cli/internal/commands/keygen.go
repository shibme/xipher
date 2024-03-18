package commands

import (
	"fmt"

	"dev.shib.me/xipher"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func toXipherKey(pubKey []byte) string {
	return xipherKeyPrefix + encode(pubKey)
}

func keygenCommand() *cobra.Command {
	if keygenCmd != nil {
		return keygenCmd
	}
	keygenCmd = &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new key pair or public key based on a password",
		Run: func(cmd *cobra.Command, args []string) {
			ignoreFlag, _ := cmd.Flags().GetBool(ignorePasswordCheckFlag.name)
			quantumSafe, _ := cmd.Flags().GetBool(quantumSafeFlag.name)
			password, err := getPasswordFromUser(true, ignoreFlag)
			if err != nil {
				exitOnError(err)
			}
			privKey, err := xipher.NewPrivateKeyForPassword(password)
			if err != nil {
				exitOnError(err)
			}
			pubKey, err := privKey.PublicKey(quantumSafe)
			if err != nil {
				exitOnError(err)
			}
			pubKeyBytes, err := pubKey.Bytes()
			if err != nil {
				exitOnError(err)
			}
			fmt.Println("Public Key:", color.HiWhiteString(toXipherKey(pubKeyBytes)))
		},
	}
	keygenCmd.Flags().BoolP(ignorePasswordCheckFlag.name, ignorePasswordCheckFlag.shorthand, false, ignorePasswordCheckFlag.usage)
	keygenCmd.Flags().BoolP(quantumSafeFlag.name, quantumSafeFlag.shorthand, false, quantumSafeFlag.usage)
	return keygenCmd
}
