package commands

import (
	"bytes"
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func toXipherText(data []byte) string {
	return xipherTxtPrefix + encode(data)
}

func fromXipherKey(xipherKey string) ([]byte, error) {
	if len(xipherKey) < len(xipherKeyPrefix) || xipherKey[:len(xipherKeyPrefix)] != xipherKeyPrefix {
		return nil, fmt.Errorf("invalid xipher key")
	}
	return decode(xipherKey[len(xipherKeyPrefix):])
}

func encryptCommand() *cobra.Command {
	if encryptCmd != nil {
		return encryptCmd
	}
	encryptCmd = &cobra.Command{
		Use:     "encrypt",
		Aliases: []string{"encr", "enc", "en", "e"},
		Short:   "Encrypts data",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	encryptCmd.AddCommand(encryptTextCommand())
	encryptCmd.AddCommand(encryptFileCommand())
	return encryptCmd
}

func encryptTextCommand() *cobra.Command {
	if encryptTxtCmd != nil {
		return encryptTxtCmd
	}
	encryptTxtCmd = &cobra.Command{
		Use:     "text",
		Aliases: []string{"txt", "t", "string", "str", "s"},
		Short:   "Encrypts a given text",
		Run: func(cmd *cobra.Command, args []string) {
			keyBytes, err := fromXipherKey(cmd.Flag(keyFlag.name).Value.String())
			if err != nil {
				exitOnError(err)
			}
			pubKey, err := xipher.ParsePublicKey(keyBytes)
			if err != nil {
				exitOnError(err)
			}
			input, err := getHiddenInputFromUser("Enter text to encrypt: ")
			if err != nil {
				exitOnError(err)
			}
			var src, dst bytes.Buffer
			src.Write(input)
			err = pubKey.EncryptStream(&dst, &src, true)
			if err != nil {
				exitOnError(err)
			}
			fmt.Println(color.GreenString(toXipherText(dst.Bytes())))
			safeExit()
		},
	}
	encryptTxtCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	encryptTxtCmd.MarkFlagRequired(keyFlag.name)
	return encryptTxtCmd
}

func encryptFileCommand() *cobra.Command {
	if encryptFileCmd != nil {
		return encryptFileCmd
	}
	encryptFileCmd = &cobra.Command{
		Use:     "file",
		Aliases: []string{"f"},
		Short:   "Encrypts a given file",
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
			keyBytes, err := fromXipherKey(keyStr)
			if err != nil {
				exitOnError(err)
			}
			pubKey, err := xipher.ParsePublicKey(keyBytes)
			if err != nil {
				exitOnError(err)
			}
			err = pubKey.EncryptStream(dst, src, compress)
			if err != nil {
				exitOnError(err)
			}
			fmt.Println("Encrypted file:", color.GreenString(dstPath))
			safeExit()
		},
	}
	encryptFileCmd.Flags().StringP(fileFlag.name, fileFlag.shorthand, "", fileFlag.usage)
	encryptFileCmd.Flags().StringP(outFlag.name, outFlag.shorthand, "", outFlag.usage)
	encryptFileCmd.Flags().StringP(keyFlag.name, keyFlag.shorthand, "", keyFlag.usage)
	encryptFileCmd.Flags().BoolP(compressFlag.name, compressFlag.shorthand, false, compressFlag.usage)
	encryptFileCmd.MarkFlagRequired(fileFlag.name)
	encryptFileCmd.MarkFlagRequired(keyFlag.name)
	return encryptFileCmd
}
