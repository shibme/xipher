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
			Short:   "Encrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				cmd.Help()
			},
		}
		encryptCmd.PersistentFlags().StringP(keyOrPwdFlag.fields())
		encryptCmd.PersistentFlags().BoolP(fetchKeyFlag.fields())
		encryptCmd.PersistentFlags().BoolP(ignorePasswordCheckFlag.fields())
		encryptCmd.AddCommand(encryptTextCommand())
		encryptCmd.AddCommand(encryptFileCommand())
		encryptCmd.AddCommand(encryptStreamCommand())
	}
	return encryptCmd
}

func getKeyPwdStr(cmd *cobra.Command) (string, error) {
	// --web-auth short-circuits the normal key/password prompt: derive the key
	// from the browser instead and use it directly as the encryption key.
	if webAuth, _ := cmd.Flags().GetBool(webAuthFlag.name); webAuth {
		xipherURL, _ := cmd.Flags().GetString(xipherURLFlag.name)
		return getSecretKeyFromWebAuth(xipherURL)
	}

	keyPwdStr := cmd.Flag(keyOrPwdFlag.name).Value.String()
	keyFlagInput := false
	if keyPwdStr == "" {
		keyPwdInput, err := getHiddenInputFromUser("Enter a public key, secret key, or password: ")
		if err != nil {
			return "", err
		}
		keyPwdStr = string(keyPwdInput)
	} else {
		keyFlagInput = true
	}

	// --fetch forces URL/domain resolution with no confirmation. Without it, a
	// value that merely looks like a bare domain is ambiguous (it could be a
	// password), so confirm before fetching it over the network.
	fetchFlag, _ := cmd.Flags().GetBool(fetchKeyFlag.name)
	if !fetchFlag && utils.LooksLikeDomain(keyPwdStr) {
		if confirmInput(fmt.Sprintf("'%s' looks like a domain. Fetch the public key from it?", keyPwdStr)) {
			fetchFlag = true
		}
	}
	if fetchFlag {
		pubKeyStr, name, err := utils.FetchPublicKeyFromURL(keyPwdStr)
		if err != nil {
			return "", err
		}
		if name != "" {
			if jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name); !jsonFormat {
				fmt.Println("Resolved recipient:", color.HiCyanString(name))
			}
		}
		return pubKeyStr, nil
	}

	keyPwdStr, isKey, name, err := utils.GetSanitisedKeyOrPwd(keyPwdStr)
	if err != nil {
		return "", err
	}
	if name != "" {
		if jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name); !jsonFormat {
			fmt.Println("Resolved recipient:", color.HiCyanString(name))
		}
	}
	if !isKey && !keyFlagInput {
		ignoreFlag, _ := cmd.Flags().GetBool(ignorePasswordCheckFlag.name)
		if !ignoreFlag {
			if err := pwdCheck(keyPwdStr); err != nil {
				return "", err
			}
		}
		confirmPwd, err := getHiddenInputFromUser("Confirm password: ")
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
			Short:   "Encrypt a text string",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				keyPwdStr, err := getKeyPwdStr(cmd)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				text, _ := cmd.Flags().GetString(textFlag.name)
				var input []byte
				switch text {
				case "":
					input, err = getHiddenInputFromUser("Enter text to encrypt: ")
				case "-":
					input, err = readBufferFromStdin("")
				default:
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
					fmt.Println("This encrypted text is safe to share over any medium.")
				}
			},
		}
		encryptTxtCmd.Flags().StringP(textFlag.fields())
		encryptTxtCmd.Flags().BoolP(webAuthFlag.fields())
		encryptTxtCmd.Flags().StringP(xipherURLFlag.fields())
	}
	return encryptTxtCmd
}

func encryptFileCommand() *cobra.Command {
	if encryptFileCmd == nil {
		encryptFileCmd = &cobra.Command{
			Use:     "file",
			Aliases: []string{"f"},
			Short:   "Encrypt a file",
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
						if !jsonFormat {
							fmt.Println("Overwriting file:", color.YellowString(dstPath))
						}
						break
					}
					if jsonFormat {
						exitOnErrorWithMessage(fmt.Sprintf("file already exists: %s", dstPath), jsonFormat)
					}
					fmt.Println("File already exists:", color.YellowString(dstPath))
					if dstPath, err = getVisibleInput("Enter a new output file path: "); err != nil {
						exitOnError(err, jsonFormat)
					}
				}
				dst := utils.NewThresholdFileWriter(dstPath, fileWriteThreshold)
				keyPwdStr, err := getKeyPwdStr(cmd)
				if err != nil {
					dst.Discard()
					exitOnError(err, jsonFormat)
				}
				compress, _ := cmd.Flags().GetBool(compressFlag.name)
				if err = utils.EncryptStream(keyPwdStr, dst, src, compress, toXipherTxt); err != nil {
					dst.Discard()
					exitOnError(err, jsonFormat)
				}
				if err = dst.Flush(); err != nil {
					dst.Discard()
					exitOnError(err, jsonFormat)
				}
				if err = dst.Close(); err != nil {
					exitOnError(err, jsonFormat)
				}
				if jsonFormat {
					resultMap := make(map[string]interface{})
					resultMap["encryptedFile"] = dstPath
					fmt.Println(toJsonString(resultMap))
				} else {
					fmt.Println("Encrypted file:", color.GreenString(dstPath))
					fmt.Println("This encrypted file is safe to share over any medium.")
				}
			},
		}
		encryptFileCmd.Flags().BoolP(overwriteFlag.fields())
		encryptFileCmd.Flags().BoolP(toXipherTxtFlag.fields())
		encryptFileCmd.Flags().StringP(sourceFileFlag.fields())
		encryptFileCmd.Flags().StringP(outputFileFlag.fields())
		encryptFileCmd.Flags().BoolP(compressFlag.fields())
		encryptFileCmd.MarkFlagRequired(sourceFileFlag.name)
		encryptFileCmd.Flags().BoolP(webAuthFlag.fields())
		encryptFileCmd.Flags().StringP(xipherURLFlag.fields())
	}
	return encryptFileCmd
}

func encryptStreamCommand() *cobra.Command {
	if encryptStreamCmd == nil {
		encryptStreamCmd = &cobra.Command{
			Use:     "stream",
			Aliases: []string{"str"},
			Short:   "Encrypt data from stdin to stdout",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				toXipherTxt, _ := cmd.Flags().GetBool(toXipherTxtFlag.name)
				var keyPwdStr string
				if webAuth, _ := cmd.Flags().GetBool(webAuthFlag.name); webAuth {
					xipherURL, _ := cmd.Flags().GetString(xipherURLFlag.name)
					var err error
					if keyPwdStr, err = getSecretKeyFromWebAuth(xipherURL); err != nil {
						exitOnError(err, jsonFormat)
					}
				} else {
					keyPwdStr = cmd.Flag(keyOrPwdFlag.name).Value.String()
					if keyPwdStr == "" {
						if keyPwdStr, _ = getSecretKeyOrPwd(false); keyPwdStr == "" {
							exitOnErrorWithMessage(fmt.Sprintf(
								"set a public key using --%s, provide a secret key or password via the %s environment variable, or use --web-auth",
								keyOrPwdFlag.name, envar_XIPHER_SECRET), jsonFormat)
						}
					}
				}
				// Resolve URL/domain key references (and embedded keys) up front;
				// EncryptStream no longer fetches remote keys itself. The stream
				// path is non-interactive, so this skips the confirmation prompts
				// that getKeyPwdStr adds for the text/file commands.
				keyPwdStr, err := utils.ResolveKeyForEncryption(keyPwdStr)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				compress, _ := cmd.Flags().GetBool(compressFlag.name)
				if err := utils.EncryptStream(keyPwdStr, os.Stdout, os.Stdin, compress, toXipherTxt); err != nil {
					exitOnError(err, jsonFormat)
				}
			},
		}
		encryptStreamCmd.Flags().BoolP(compressFlag.fields())
		encryptStreamCmd.Flags().BoolP(toXipherTxtFlag.fields())
		encryptStreamCmd.Flags().BoolP(webAuthFlag.fields())
		encryptStreamCmd.Flags().StringP(xipherURLFlag.fields())
	}
	return encryptStreamCmd
}
