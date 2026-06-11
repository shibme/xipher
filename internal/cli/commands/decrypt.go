package commands

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"xipher.org/xipher/internal/utils"
)

func decryptCommand() *cobra.Command {
	if decryptCmd == nil {
		decryptCmd = &cobra.Command{
			Use:     "decrypt",
			Aliases: []string{"decr", "dec", "de", "d"},
			Short:   "Decrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				cmd.Help()
			},
		}
		decryptCmd.AddCommand(decryptTextCommand())
		decryptCmd.AddCommand(decryptFileCommand())
		decryptCmd.AddCommand(decryptStreamCommand())
	}
	return decryptCmd
}

func getSecretKeyOrPwd(interactive bool) (string, error) {
	if secret == nil {
		secret = new(string)
		*secret = os.Getenv(envar_XIPHER_SECRET)
		if *secret == "" {
			if interactive {
				passwordOrSecretKey, err := getPasswordOrSecretKeyFromUser(false, true)
				if err != nil {
					return "", err
				}
				*secret = string(passwordOrSecretKey)
			}
		}
	}
	return *secret, nil
}

// resolveSecretKey returns the secret key to use for the operation. When the
// --web-auth flag is set it launches the browser-assisted flow; otherwise it
// falls back to the normal env-var / interactive prompt path.
func resolveSecretKey(cmd *cobra.Command, interactive bool) (string, error) {
	webAuth, _ := cmd.Flags().GetBool(webAuthFlag.name)
	if webAuth {
		xipherURL, _ := cmd.Flags().GetString(xipherURLFlag.name)
		return getSecretKeyFromWebAuth(xipherURL)
	}
	return getSecretKeyOrPwd(interactive)
}

func decryptTextCommand() *cobra.Command {
	if decryptTxtCmd == nil {
		decryptTxtCmd = &cobra.Command{
			Use:     "text",
			Aliases: []string{"txt", "t", "string", "str", "s"},
			Short:   "Decrypt an encrypted text string",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				xipherText := cmd.Flag(ciphertextFlag.name).Value.String()
				secretKeyOrPwd, err := resolveSecretKey(cmd, true)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				data, err := utils.DecryptData(secretKeyOrPwd, xipherText)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				if jsonFormat {
					resultMap := make(map[string]string)
					resultMap["decryptedText"] = string(data)
					fmt.Println(toJsonString(resultMap))
				} else {
					fmt.Println(color.GreenString(string(data)))
				}
			},
		}
		decryptTxtCmd.Flags().StringP(ciphertextFlag.fields())
		decryptTxtCmd.MarkFlagRequired(ciphertextFlag.name)
		decryptTxtCmd.Flags().BoolP(webAuthFlag.fields())
		decryptTxtCmd.Flags().StringP(xipherURLFlag.fields())
	}
	return decryptTxtCmd
}

func decryptFileCommand() *cobra.Command {
	if decryptFileCmd == nil {
		decryptFileCmd = &cobra.Command{
			Use:     "file",
			Aliases: []string{"f"},
			Short:   "Decrypt an encrypted file",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				overwrite, _ := cmd.Flags().GetBool(overwriteFlag.name)
				srcPath := cmd.Flag(sourceFileFlag.name).Value.String()
				dstPath := cmd.Flag(outputFileFlag.name).Value.String()
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
				src, err := os.Open(srcPath)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				dst := utils.NewThresholdFileWriter(dstPath, fileWriteThreshold)
				secretKeyOrPwd, err := resolveSecretKey(cmd, true)
				if err != nil {
					dst.Discard()
					exitOnError(err, jsonFormat)
				}
				if err = utils.DecryptStream(secretKeyOrPwd, dst, src); err != nil {
					dst.Discard()
					exitOnError(err, jsonFormat)
				}
				if err = dst.Close(); err != nil {
					exitOnError(err, jsonFormat)
				}
				if jsonFormat {
					resultMap := make(map[string]interface{})
					resultMap["decryptedFile"] = dstPath
					fmt.Println(toJsonString(resultMap))
				} else {
					fmt.Println("Decrypted file:", color.GreenString(dstPath))
				}
			},
		}
		decryptFileCmd.Flags().BoolP(overwriteFlag.fields())
		decryptFileCmd.Flags().StringP(sourceFileFlag.fields())
		decryptFileCmd.Flags().StringP(outputFileFlag.fields())
		decryptFileCmd.MarkFlagRequired(sourceFileFlag.name)
		decryptFileCmd.Flags().BoolP(webAuthFlag.fields())
		decryptFileCmd.Flags().StringP(xipherURLFlag.fields())
	}
	return decryptFileCmd
}

func decryptStreamCommand() *cobra.Command {
	if decryptStreamCmd == nil {
		decryptStreamCmd = &cobra.Command{
			Use:     "stream",
			Aliases: []string{"str"},
			Short:   "Decrypt data from stdin to stdout",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				webAuth, _ := cmd.Flags().GetBool(webAuthFlag.name)
				var secretKeyOrPwd string
				if webAuth {
					xipherURL, _ := cmd.Flags().GetString(xipherURLFlag.name)
					var err error
					if secretKeyOrPwd, err = getSecretKeyFromWebAuth(xipherURL); err != nil {
						exitOnError(err, jsonFormat)
					}
				} else {
					secretKeyOrPwd, _ = getSecretKeyOrPwd(false)
					if secretKeyOrPwd == "" {
						exitOnErrorWithMessage(fmt.Sprintf(
							"provide a secret key or password via the %s environment variable or use --web-auth", envar_XIPHER_SECRET), jsonFormat)
					}
				}
				if err := utils.DecryptStream(secretKeyOrPwd, os.Stdout, os.Stdin); err != nil {
					exitOnError(err, jsonFormat)
				}
			},
		}
		decryptStreamCmd.Flags().BoolP(webAuthFlag.fields())
		decryptStreamCmd.Flags().StringP(xipherURLFlag.fields())
	}
	return decryptStreamCmd
}
