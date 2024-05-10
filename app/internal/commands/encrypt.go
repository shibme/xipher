package commands

import (
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"dev.shib.me/xipher/app/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func pubKeyFromFlagValue(xipherPubKeyFlagValue string) (*xipher.PublicKey, error) {
	pubKeyStr := xipherPubKeyFlagValue
	if _, err := os.Stat(xipherPubKeyFlagValue); err == nil {
		if keyFileData, err := os.ReadFile(xipherPubKeyFlagValue); err == nil {
			pubKeyStr = string(keyFileData)
		}
	}
	return utils.PubKeyFromStr(pubKeyStr)
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
	encryptCmd.PersistentFlags().StringP(publicKeyFlag.name, publicKeyFlag.shorthand, "", publicKeyFlag.usage)
	encryptCmd.MarkPersistentFlagRequired(publicKeyFlag.name)
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
			pubKey, err := pubKeyFromFlagValue(cmd.Flag(publicKeyFlag.name).Value.String())
			if err != nil {
				exitOnError(err)
			}
			input, err := getHiddenInputFromUser("Enter text to encrypt: ")
			if err != nil {
				exitOnError(err)
			}
			ct, err := utils.EncryptDataWithPubKey(pubKey, input)
			if err != nil {
				exitOnError(err)
			}
			fmt.Println(color.GreenString(ct))
			fmt.Println("It is completely safe to share this encrypted text over any medium.")
			safeExit()
		},
	}
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
				dstPath = srcPath + xipherFileExt
			}
			for {
				if _, err = os.Stat(dstPath); os.IsNotExist(err) {
					break
				}
				fmt.Println("File already exists:", color.YellowString(dstPath))
				dstPath, err = getVisibleInput("Enter a new file path ending with .xipher: ")
				if err != nil {
					exitOnError(err)
				}
			}
			dst, err := os.Create(dstPath)
			if err != nil {
				exitOnError(err)
			}
			compress, _ := cmd.Flags().GetBool(compressFlag.name)
			pubKey, err := pubKeyFromFlagValue(cmd.Flag(publicKeyFlag.name).Value.String())
			if err != nil {
				exitOnError(err)
			}
			err = pubKey.EncryptStream(dst, src, compress)
			if err != nil {
				exitOnError(err)
			}
			fmt.Println("Encrypted file:", color.GreenString(dstPath))
			fmt.Println("It is completely safe to share this encrypted file over any medium.")
			safeExit()
		},
	}
	encryptFileCmd.Flags().StringP(fileFlag.name, fileFlag.shorthand, "", fileFlag.usage)
	encryptFileCmd.Flags().StringP(outFlag.name, outFlag.shorthand, "", outFlag.usage)
	encryptFileCmd.Flags().BoolP(compressFlag.name, compressFlag.shorthand, false, compressFlag.usage)
	encryptFileCmd.MarkFlagRequired(fileFlag.name)
	return encryptFileCmd
}
