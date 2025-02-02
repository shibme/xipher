package commands

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"xipher.org/xipher/utils"
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
	encryptCmd.PersistentFlags().StringP(keyOrPwdFlag.fields())
	encryptCmd.PersistentFlags().BoolP(ignorePasswordCheckFlag.fields())
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
	var isKey bool
	keyPwdStr, isKey = utils.GetSanitisedKeyOrPwd(keyPwdStr)
	if !isKey {
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
			jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
			keyPwdStr, err := getKeyPwdStr(cmd)
			if err != nil {
				exitOnError(err, jsonFormat)
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
				exitOnError(err, jsonFormat)
			}
			ctStr, ctUrl, err := utils.EncryptData(keyPwdStr, input, true)
			if err != nil {
				exitOnError(err, jsonFormat)
			}
			if jsonFormat {
				resultMap := make(map[string]interface{})
				resultMap["encryptedText"] = ctStr
				if ctUrl != "" {
					resultMap["encryptedTextUrl"] = ctUrl
				}
				fmt.Println(toJsonString(resultMap))
			} else {
				fmt.Println("Encrypted text:", color.GreenString(ctStr))
				if ctUrl != "" {
					fmt.Println("Encrypted text URL:", color.HiCyanString(ctUrl))
				}
				fmt.Println("It is completely safe to share this encrypted text over any medium.")
			}
		},
	}
	encryptTxtCmd.Flags().StringP(textFlag.fields())
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
			jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
			overwrite, _ := cmd.Flags().GetBool(overwriteFlag.name)
			srcPath := cmd.Flag(sourceFileFlag.name).Value.String()
			src, err := os.Open(srcPath)
			if err != nil {
				exitOnError(err, jsonFormat)
			}
			dstPath := cmd.Flag(outputFileFlag.name).Value.String()
			if dstPath == "" {
				dstPath = srcPath + xipherFileExt
			}
			for {
				if _, err = os.Stat(dstPath); os.IsNotExist(err) {
					break
				}
				if overwrite {
					fmt.Println("Overwriting file:", color.YellowString(dstPath))
					break
				}
				fmt.Println("File already exists:", color.YellowString(dstPath))
				if dstPath, err = getVisibleInput("Provide a new destination file ending with .xipher: "); err != nil {
					exitOnError(err, jsonFormat)
				}
			}
			dst, err := os.Create(dstPath)
			if err != nil {
				exitOnError(err, jsonFormat)
			}
			keyPwdStr, err := getKeyPwdStr(cmd)
			if err != nil {
				exitOnError(err, jsonFormat)
			}
			compress, _ := cmd.Flags().GetBool(compressFlag.name)
			if err = utils.EncryptStream(keyPwdStr, dst, src, compress); err != nil {
				dst.Close()
				os.Remove(dstPath)
				exitOnError(err, jsonFormat)
			}
			if jsonFormat {
				resultMap := make(map[string]interface{})
				resultMap["encryptedFile"] = dstPath
			} else {
				fmt.Println("Encrypted file:", color.GreenString(dstPath))
				fmt.Println("It is completely safe to share this encrypted file over any medium.")
			}
		},
	}
	encryptFileCmd.Flags().BoolP(overwriteFlag.fields())
	encryptFileCmd.Flags().StringP(sourceFileFlag.fields())
	encryptFileCmd.Flags().StringP(outputFileFlag.fields())
	encryptFileCmd.Flags().BoolP(compressFlag.fields())
	encryptFileCmd.MarkFlagRequired(sourceFileFlag.name)
	return encryptFileCmd
}
