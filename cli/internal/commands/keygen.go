package commands

import (
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
				fmt.Print("Password: ")
				var password []byte
				password, err = term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					exitOnErrorWithMessage("Error reading password.")
				}
				fmt.Println()
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
			fmt.Println("Public Key:", encode(pubKey.Bytes()))
		},
	}
	keygenCmd.Flags().BoolP(passwordFlag.name, passwordFlag.shorthand, false, passwordFlag.usage)
	return keygenCmd
}
