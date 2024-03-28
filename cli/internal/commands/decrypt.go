package commands

import (
	"bytes"
	"fmt"
	"os"

	"dev.shib.me/xipher"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func fromXipherText(xipherText string) ([]byte, error) {
	if len(xipherText) < len(xipherTxtPrefix) || xipherText[:len(xipherTxtPrefix)] != xipherTxtPrefix {
		return nil, fmt.Errorf("invalid xipher text")
	}
	return decode(xipherText[len(xipherTxtPrefix):])
}

func decryptCommand() *cobra.Command {
	if decryptCmd != nil {
		return decryptCmd
	}
	decryptCmd = &cobra.Command{
		Use:     "decrypt",
		Aliases: []string{"decr", "dec", "de", "d"},
		Short:   "Decrypts the encrypted data",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	decryptCmd.AddCommand(decryptTextCommand())
	decryptCmd.AddCommand(decryptFileCommand())
	return decryptCmd
}

func decryptTextCommand() *cobra.Command {
	if decryptTxtCmd != nil {
		return decryptTxtCmd
	}
	decryptTxtCmd = &cobra.Command{
		Use:     "text",
		Aliases: []string{"txt", "t", "string", "str", "s"},
		Short:   "Decrypts a xipher encrypted text",
		Run: func(cmd *cobra.Command, args []string) {
			xipherText, err := fromXipherText(cmd.Flag(ciphertextFlag.name).Value.String())
			if err != nil {
				exitOnError(err)
			}
			var src, dst bytes.Buffer
			src.Write(xipherText)
			password, err := getPasswordFromUser(false, true)
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
			fmt.Println(color.GreenString(dst.String()))
			safeExit()
		},
	}
	decryptTxtCmd.Flags().StringP(ciphertextFlag.name, ciphertextFlag.shorthand, "", ciphertextFlag.usage)
	decryptTxtCmd.MarkFlagRequired(ciphertextFlag.name)
	return decryptTxtCmd
}

func decryptFileCommand() *cobra.Command {
	if decryptFileCmd != nil {
		return decryptFileCmd
	}
	decryptFileCmd = &cobra.Command{
		Use:     "file",
		Aliases: []string{"f"},
		Short:   "Decrypts a xipher encrypted file",
		Run: func(cmd *cobra.Command, args []string) {
			srcPath := cmd.Flag(fileFlag.name).Value.String()
			dstPath := cmd.Flag(outFlag.name).Value.String()
			if dstPath == "" {
				if idx := len(srcPath) - len(xipherFileExt); idx > 0 {
					if srcPath[idx:] == xipherFileExt {
						dstPath = srcPath[:idx]
					}
				}
			}
			var err error
			for {
				if _, err = os.Stat(dstPath); os.IsNotExist(err) {
					break
				}
				fmt.Println("File already exists:", color.YellowString(dstPath))
				dstPath, err = getVisibleInput("Enter a new file path for the decrypted file: ")
				if err != nil {
					exitOnError(err)
				}
			}
			src, err := os.Open(srcPath)
			if err != nil {
				exitOnError(err)
			}
			dst, err := os.Create(dstPath)
			if err != nil {
				exitOnError(err)
			}
			password, err := getPasswordFromUser(false, true)
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
			fmt.Println("Decrypted file:", color.GreenString(dstPath))
			safeExit()
		},
	}
	decryptFileCmd.Flags().StringP(fileFlag.name, fileFlag.shorthand, "", fileFlag.usage)
	decryptFileCmd.Flags().StringP(outFlag.name, outFlag.shorthand, "", outFlag.usage)
	decryptFileCmd.MarkFlagRequired(fileFlag.name)
	return decryptFileCmd
}
