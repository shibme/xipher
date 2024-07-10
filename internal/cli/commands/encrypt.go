package commands

import (
	"fmt"
	"os"

	"dev.shib.me/xipher/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

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
	encryptCmd.PersistentFlags().StringP(keyOrPwdFlag.flagFields())
	encryptCmd.PersistentFlags().BoolP(ignorePasswordCheckFlag.flagFields())
	encryptCmd.AddCommand(encryptTextCommand())
	encryptCmd.AddCommand(encryptFileCommand())
	return encryptCmd
}

func getKeyPwdStr(cmd *cobra.Command) (string, error) {
	keyPwdStr := cmd.Flag(keyOrPwdFlag.name).Value.String()
	if keyPwdStr == "" {
		keyPwdInput, err := getHiddenInputFromUser("Enter a public key, secret key or a password: ")
		if err != nil {
			return "", err
		}
		keyPwdStr = string(keyPwdInput)
	}
	if !utils.IsPubKeyStr(keyPwdStr) && !utils.IsSecretKeyStr(keyPwdStr) {
		ignoreFlag, _ := cmd.Flags().GetBool(ignorePasswordCheckFlag.name)
		if !ignoreFlag {
			if err := pwdCheck(keyPwdStr); err != nil {
				return "", err
			}
		}
		confirmPwd, err := getHiddenInputFromUser("Confirm the password: ")
		if err != nil {
			return "", err
		}
		if string(confirmPwd) != keyPwdStr {
			return "", fmt.Errorf("passwords do not match")
		}
	}
	return keyPwdStr, nil
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
			keyPwdStr, err := getKeyPwdStr(cmd)
			if err != nil {
				exitOnError(err)
			}
			text, _ := cmd.Flags().GetString(textFlag.name)
			var input []byte
			if text == "" {
				input, err = getHiddenInputFromUser("Enter text to encrypt: ")
			} else if text == "-" {
				input, err = readBufferFromStdin("")
			} else {
				input = []byte(text)
			}
			if err != nil {
				exitOnError(err)
			}
			ct, err := utils.EncryptData(keyPwdStr, input)
			if err != nil {
				exitOnError(err)
			}
			fmt.Println(color.GreenString(ct))
			fmt.Println("It is completely safe to share this encrypted text over any medium.")
			safeExit()
		},
	}
	encryptTxtCmd.Flags().StringP(textFlag.flagFields())
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
			keyPwdStr, err := getKeyPwdStr(cmd)
			if err != nil {
				exitOnError(err)
			}
			compress, _ := cmd.Flags().GetBool(compressFlag.name)
			if err = utils.EncryptStream(keyPwdStr, dst, src, compress); err != nil {
				exitOnError(err)
			}
			fmt.Println("Encrypted file:", color.GreenString(dstPath))
			fmt.Println("It is completely safe to share this encrypted file over any medium.")
			safeExit()
		},
	}
	encryptFileCmd.Flags().StringP(fileFlag.flagFields())
	encryptFileCmd.Flags().StringP(outFlag.flagFields())
	encryptFileCmd.Flags().BoolP(compressFlag.flagFields())
	encryptFileCmd.MarkFlagRequired(fileFlag.name)
	return encryptFileCmd
}
