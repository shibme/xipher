package commands

import (
	"bytes"
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"github.com/spf13/cobra"
)

func decryptCommand() *cobra.Command {
	if decryptCmd != nil {
		return decryptCmd
	}
	decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypts the data",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	decryptCmd.AddCommand(decryptStringCommand())
	decryptCmd.AddCommand(decryptFileCommand())
	return decryptCmd
}

func decryptStringCommand() *cobra.Command {
	if decryptStrCmd != nil {
		return decryptStrCmd
	}
	decryptStrCmd = &cobra.Command{
		Use:     "string",
		Aliases: []string{"str"},
		Short:   "Decrypts a xipher encrypted string",
		Run: func(cmd *cobra.Command, args []string) {
			cipheredStr, err := decode(cmd.Flag(stringFlag.name).Value.String())
			if err != nil {
				exitOnError(err)
			}
			var src, dst bytes.Buffer
			src.Write(cipheredStr)
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
				err = privKey.DecryptStream(&dst, &src)
				if err != nil {
					exitOnError(err)
				}
			} else {
				// Get password from user
				password, err := getPasswordFromUser(false)
				if err != nil {
					exitOnError(err)
				}
				privKey, err := xipher.NewPrivateKeyForPassword(password)
				if err != nil {
					exitOnError(err)
				}
				err = privKey.DecryptStream(&dst, &src)
				if err != nil {
					exitOnError(err)
				}
			}
			fmt.Println(dst.String())
			safeExit()
		},
	}
	decryptStrCmd.Flags().StringP(stringFlag.name, stringFlag.shorthand, "", stringFlag.usage)
	decryptStrCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	decryptStrCmd.MarkFlagRequired(stringFlag.name)
	return decryptStrCmd
}

func decryptFileCommand() *cobra.Command {
	if decryptFileCmd != nil {
		return decryptFileCmd
	}
	decryptFileCmd = &cobra.Command{
		Use:   "file",
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
					exitOnError(err)
				}
			} else {
				// Get password from user
				password, err := getPasswordFromUser(false)
				if err != nil {
					exitOnError(err)
				}
				privKey, err := xipher.NewPrivateKeyForPassword(password)
				if err != nil {
					exitOnError(err)
				}
				err = privKey.DecryptStream(dst, src)
				if err != nil {
					exitOnError(err)
				}
			}
			safeExit()
		},
	}
	decryptFileCmd.Flags().StringP(fileFlag.name, fileFlag.shorthand, "", fileFlag.usage)
	decryptFileCmd.Flags().StringP(outFlag.name, outFlag.shorthand, "", outFlag.usage)
	decryptFileCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	decryptFileCmd.MarkFlagRequired(fileFlag.name)
	decryptFileCmd.MarkFlagRequired(outFlag.name)
	return decryptFileCmd
}
