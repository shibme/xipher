package commands

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"xipher.org/xipher/internal/utils"
)

func encryptCommand() *cobra.Command {
	if encryptCmd == nil {
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
		encryptCmd.AddCommand(encryptStreamCommand())
	}
	return encryptCmd
}

func getKeyPwdStr(cmd *cobra.Command) (string, error) {
	keyPwdStr := cmd.Flag(keyOrPwdFlag.name).Value.String()
	keyFlagInput := false
	if keyPwdStr == "" {
		keyPwdInput, err := getHiddenInputFromUser("Enter a public key, secret key or a password: ")
		if err != nil {
			return "", err
		}
		keyPwdStr = string(keyPwdInput)
	} else {
		keyFlagInput = true
	}
	var isKey bool
	keyPwdStr, isKey = utils.GetSanitisedKeyOrPwd(keyPwdStr)
	if !isKey && !keyFlagInput {
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
	if encryptTxtCmd == nil {
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
	}
	return encryptTxtCmd
}

func encryptFileCommand() *cobra.Command {
	if encryptFileCmd == nil {
		encryptFileCmd = &cobra.Command{
			Use:     "file",
			Aliases: []string{"f"},
			Short:   "Encrypts a given file",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				toXipherTxt, _ := cmd.Flags().GetBool(toXipherTxtFlag.name)
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
				if err = utils.EncryptStream(keyPwdStr, dst, src, compress, toXipherTxt); err != nil {
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
		encryptFileCmd.Flags().BoolP(toXipherTxtFlag.fields())
		encryptFileCmd.Flags().StringP(sourceFileFlag.fields())
		encryptFileCmd.Flags().StringP(outputFileFlag.fields())
		encryptFileCmd.Flags().BoolP(compressFlag.fields())
		encryptFileCmd.MarkFlagRequired(sourceFileFlag.name)
	}
	return encryptFileCmd
}

func encryptStreamCommand() *cobra.Command {
	if encryptStreamCmd == nil {
		encryptStreamCmd = &cobra.Command{
			Use:   "stream",
			Short: "Encryts data from the standard input stream and writes to the standard output stream",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				toXipherTxt, _ := cmd.Flags().GetBool(toXipherTxtFlag.name)
				keyPwdStr := cmd.Flag(keyOrPwdFlag.name).Value.String()
				if keyPwdStr == "" {
					if keyPwdStr, _ = getSecretKeyOrPwd(false); keyPwdStr == "" {
						exitOnErrorWithMessage(fmt.Sprintf(
							"Please set a public key using the --%s flag or provide a secret key or password using the environment variable %s",
							keyOrPwdFlag.name, envar_XIPHER_SECRET), jsonFormat)
					}
				}
				compress, _ := cmd.Flags().GetBool(compressFlag.name)
				if err := utils.EncryptStream(keyPwdStr, os.Stdout, os.Stdin, compress, toXipherTxt); err != nil {
					exitOnError(err, jsonFormat)
				}
			},
		}
		encryptStreamCmd.Flags().BoolP(compressFlag.fields())
		encryptStreamCmd.Flags().BoolP(toXipherTxtFlag.fields())
	}
	return encryptStreamCmd
}
