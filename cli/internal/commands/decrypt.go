package commands

import (
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func decryptCommand() *cobra.Command {
	if decryptCmd != nil {
		return decryptCmd
	}
	decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypts a xipher encrypted file",
		Run: func(cmd *cobra.Command, args []string) {
			srcPath := cmd.Flag(fileFlag.name).Value.String()
			dstPath := cmd.Flag(outFlag.name).Value.String()
			// Check match between src and dst
			if srcPath == dstPath {
				exitOnErrorWithMessage("Source and destination paths cannot be the same.")
			}
			src, err := os.Open(srcPath)
			if err != nil {
				exitOnError(err)
			}
			dst, err := os.Create(dstPath)
			if err != nil {
				exitOnError(err)
			}
			keyStr := cmd.Flag(keyFlag.name).Value.String()
			if keyStr != "" {
				keyBytes, err := decode(keyStr)
				if err != nil {
					exitOnError(err)
				}
				privKey, err := xipher.ParsePrivateKey(keyBytes)
				if err != nil {
					exitOnError(err)
				}
				err = privKey.DecryptStream(dst, src)
				if err != nil {
					exitOnErrorWithMessage("Error decrypting file.")
				}
			} else {
				// Get password from user
				fmt.Print("Password: ")
				var password []byte
				password, err = term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					exitOnErrorWithMessage("Error reading password.")
				}
				fmt.Println()
				privKey, err := xipher.NewPrivateKeyForPassword(password)
				if err != nil {
					exitOnError(err)
				}
				err = privKey.DecryptStream(dst, src)
				if err != nil {
					exitOnErrorWithMessage("Error decrypting file.")
				}
			}
			safeExit()
		},
	}
	decryptCmd.Flags().StringP(fileFlag.name, fileFlag.shorthand, "", fileFlag.usage)
	decryptCmd.Flags().StringP(outFlag.name, outFlag.shorthand, "", outFlag.usage)
	decryptCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	decryptCmd.MarkFlagRequired(fileFlag.name)
	decryptCmd.MarkFlagRequired(outFlag.name)
	return decryptCmd
}
