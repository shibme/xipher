package commands

import (
	"fmt"
	"os"

	"dev.shib.me/xipher"
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
			pwdFlag, err := cmd.Flags().GetBool(passwordFlag.name)
			if err != nil {
				exitOnError(err)
			}
			var privKey *xipher.PrivateKey
			if pwdFlag {
				// Get password from user
				password, err := getPasswordFromUser(true)
				if err != nil {
					exitOnError(err)
				}
				privKey, err = xipher.NewPrivateKeyForPassword(password)
				if err != nil {
					exitOnError(err)
				}
			} else {
				privKey, err = xipher.NewPrivateKey()
				if err != nil {
					exitOnError(err)
				}
			}
			pubKey, err := privKey.PublicKey()
			if err != nil {
				exitOnError(err)
			}
			pubKeyStr := encode(pubKey.Bytes())
			fmt.Println("Public Key:", pubKeyStr)
			if privKeyBytes, err := privKey.Bytes(); err == nil {
				fileName := fmt.Sprintf("xipher_%s.privkey", pubKeyStr)
				if err := os.WriteFile(fileName, []byte(encode(privKeyBytes)), 0644); err != nil {
					exitOnError(err)
				}
				fmt.Println("Private Key file:", fileName)
			}
		},
	}
	keygenCmd.Flags().BoolP(passwordFlag.name, passwordFlag.shorthand, false, passwordFlag.usage)
	return keygenCmd
}
