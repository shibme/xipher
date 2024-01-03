package commands

import (
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func encryptCommand() *cobra.Command {
	if encryptCmd != nil {
		return encryptCmd
	}
	encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypts a file",
		Run: func(cmd *cobra.Command, args []string) {
			srcPath := cmd.Flag(fileFlag.name).Value.String()
			src, err := os.Open(srcPath)
			if err != nil {
				exitOnError(err)
			}
			dstPath := cmd.Flag(outFlag.name).Value.String()
			if dstPath == "" {
				dstPath = srcPath + ".xipher"
			}
			dst, err := os.Create(dstPath)
			if err != nil {
				exitOnError(err)
			}
			keyStr := cmd.Flag(keyFlag.name).Value.String()
			compress, _ := cmd.Flags().GetBool(compressFlag.name)
			if keyStr != "" {
				keyBytes, err := decode(keyStr)
				if err != nil {
					exitOnError(err)
				}
				if len(keyBytes) == xipher.PrivateKeyLength {
					privKey, err := xipher.ParsePrivateKey(keyBytes)
					if err != nil {
						exitOnError(err)
					}
					err = privKey.EncryptStream(dst, src, compress)
					if err != nil {
						exitOnError(err)
					}
				} else {
					pubKey, err := xipher.ParsePublicKey(keyBytes)
					if err != nil {
						exitOnError(err)
					}
					err = pubKey.EncryptStream(dst, src, compress)
					if err != nil {
						exitOnError(err)
					}
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
				err = privKey.EncryptStream(dst, src, compress)
				if err != nil {
					exitOnError(err)
				}
			}
			safeExit()
		},
	}
	encryptCmd.Flags().StringP(fileFlag.name, fileFlag.shorthand, "", fileFlag.usage)
	encryptCmd.Flags().StringP(outFlag.name, outFlag.shorthand, "", outFlag.usage)
	encryptCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	encryptCmd.Flags().BoolP(compressFlag.name, compressFlag.shorthand, false, compressFlag.usage)
	encryptCmd.MarkFlagRequired(fileFlag.name)
	return encryptCmd
}
