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
			Short:   "Decrypts the encrypted data",
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

func decryptTextCommand() *cobra.Command {
	if decryptTxtCmd == nil {
		decryptTxtCmd = &cobra.Command{
			Use:     "text",
			Aliases: []string{"txt", "t", "string", "str", "s"},
			Short:   "Decrypts a xipher encrypted text",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				xipherText := cmd.Flag(ciphertextFlag.name).Value.String()
				secretKeyOrPwd, err := getSecretKeyOrPwd(true)
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
	}
	return decryptTxtCmd
}

func decryptFileCommand() *cobra.Command {
	if decryptFileCmd == nil {
		decryptFileCmd = &cobra.Command{
			Use:     "file",
			Aliases: []string{"f"},
			Short:   "Decrypts a xipher encrypted file",
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
						fmt.Println("Overwriting file:", color.YellowString(dstPath))
						break
					}
					fmt.Println("File already exists:", color.YellowString(dstPath))
					if dstPath, err = getVisibleInput("Enter a new file path for the decrypted file: "); err != nil {
						exitOnError(err, jsonFormat)
					}
				}
				src, err := os.Open(srcPath)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				dst, err := os.Create(dstPath)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				secretKeyOrPwd, err := getSecretKeyOrPwd(true)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				if err = utils.DecryptStream(secretKeyOrPwd, dst, src); err != nil {
					dst.Close()
					os.Remove(dstPath)
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
	}
	return decryptFileCmd
}

func decryptStreamCommand() *cobra.Command {
	if decryptStreamCmd == nil {
		decryptStreamCmd = &cobra.Command{
			Use:   "stream",
			Short: "Decrypts the encrypted data from the standard input and writes to the standard output",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				secretKeyOrPwd, _ := getSecretKeyOrPwd(false)
				if secretKeyOrPwd == "" {
					exitOnErrorWithMessage(fmt.Sprintf(
						"Please provide a secret key or password using the environment variable %s", envar_XIPHER_SECRET), jsonFormat)
				}
				if err := utils.DecryptStream(secretKeyOrPwd, os.Stdout, os.Stdin); err != nil {
					exitOnError(err, jsonFormat)
				}
			},
		}
	}
	return decryptStreamCmd
}
