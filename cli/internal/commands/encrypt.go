package commands

import (
	"bytes"
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"github.com/spf13/cobra"
)

func encryptCommand() *cobra.Command {
	if encryptCmd != nil {
		return encryptCmd
	}
	encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypts the data",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	encryptCmd.AddCommand(encryptStringCommand())
	encryptCmd.AddCommand(encryptFileCommand())
	return encryptCmd
}

func encryptStringCommand() *cobra.Command {
	if encryptStrCmd != nil {
		return encryptStrCmd
	}
	encryptStrCmd = &cobra.Command{
		Use:     "string",
		Aliases: []string{"str"},
		Short:   "Encrypts a given string",
		Run: func(cmd *cobra.Command, args []string) {
			inputStr := cmd.Flag(stringFlag.name).Value.String()
			var src, dst bytes.Buffer
			src.WriteString(inputStr)
			keyStr := cmd.Flag(keyFlag.name).Value.String()
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
					err = privKey.EncryptStream(&dst, &src, true)
					if err != nil {
						exitOnError(err)
					}
				} else {
					pubKey, err := xipher.ParsePublicKey(keyBytes)
					if err != nil {
						exitOnError(err)
					}
					err = pubKey.EncryptStream(&dst, &src, true)
					if err != nil {
						exitOnError(err)
					}
				}
			} else {
				// Get password from user
				password, err := getPasswordFromUser(true)
				if err != nil {
					exitOnError(err)
				}
				privKey, err := xipher.NewPrivateKeyForPassword(password)
				if err != nil {
					exitOnError(err)
				}
				err = privKey.EncryptStream(&dst, &src, true)
				if err != nil {
					exitOnError(err)
				}
			}
			fmt.Println(encode(dst.Bytes()))
			safeExit()
		},
	}
	encryptStrCmd.Flags().StringP(stringFlag.name, stringFlag.shorthand, "", stringFlag.usage)
	encryptStrCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	encryptStrCmd.MarkFlagRequired(stringFlag.name)
	return encryptStrCmd
}

func encryptFileCommand() *cobra.Command {
	if encryptFileCmd != nil {
		return encryptFileCmd
	}
	encryptFileCmd = &cobra.Command{
		Use:   "file",
		Short: "Encrypts a given file",
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
				password, err := getPasswordFromUser(true)
				if err != nil {
					exitOnError(err)
				}
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
	encryptFileCmd.Flags().StringP(fileFlag.name, fileFlag.shorthand, "", fileFlag.usage)
	encryptFileCmd.Flags().StringP(outFlag.name, outFlag.shorthand, "", outFlag.usage)
	encryptFileCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	encryptFileCmd.Flags().BoolP(compressFlag.name, compressFlag.shorthand, false, compressFlag.usage)
	encryptFileCmd.MarkFlagRequired(fileFlag.name)
	return encryptFileCmd
}
