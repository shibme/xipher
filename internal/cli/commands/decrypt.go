package commands

import (
	"fmt"
	"os"

	"dev.shib.me/xipher/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

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

func getSecret() (string, error) {
	if secret == nil {
		secret = new(string)
		*secret = os.Getenv(envar_XIPHER_SECRET)
		if *secret == "" {
			password, err := getPasswordFromUser(false, true)
			if err != nil {
				return "", err
			}
			*secret = string(password)
		}
	}
	return *secret, nil
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
			xipherText := cmd.Flag(ciphertextFlag.name).Value.String()
			secret, err := getSecret()
			if err != nil {
				exitOnError(err)
			}
			text, err := utils.DecryptData(secret, xipherText)
			if err != nil {
				exitOnError(err)
			}
			fmt.Println(color.GreenString(text))
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
			secret, err := getSecret()
			if err != nil {
				exitOnError(err)
			}
			privKey, err := utils.SecretKeyFromSecret(secret)
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
