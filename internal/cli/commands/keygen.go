package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"xipher.org/xipher/utils"
)

func keygenCommand() *cobra.Command {
	if keygenCmd == nil {
		keygenCmd = &cobra.Command{
			Use:   "keygen",
			Short: "Generate a new random key pair or a public key based on a given password or secret key",
			Run: func(cmd *cobra.Command, args []string) {
				jsonFormat, _ := cmd.Flags().GetBool(jsonFlag.name)
				resultMap := make(map[string]interface{})
				publicKeyFilePath := cmd.Flag(publicKeyFileFlag.name).Value.String()
				ignoreFlag, _ := cmd.Flags().GetBool(ignorePasswordCheckFlag.name)
				autoGen, _ := cmd.Flags().GetBool(autoGenerateSecretKey.name)
				quantumSafe, _ := cmd.Flags().GetBool(quantumSafeFlag.name)
				var secret string
				var err error
				if autoGen {
					if secret, err = utils.NewSecretKey(); err != nil {
						exitOnError(err, jsonFormat)
					}
					if jsonFormat {
						resultMap["secretKey"] = secret
					} else {
						fmt.Println("Secret Key:", color.HiBlackString(secret))
					}
				} else {
					password, err := getPasswordOrSecretKeyFromUser(true, ignoreFlag)
					if err != nil {
						exitOnError(err, jsonFormat)
					}
					secret = string(password)
				}
				pubKeyStr, pubKeyUrl, err := utils.GetPublicKey(secret, quantumSafe)
				if err != nil {
					exitOnError(err, jsonFormat)
				}
				if publicKeyFilePath != "" {
					if !strings.HasSuffix(publicKeyFilePath, xipherPubKeyFileExt) {
						publicKeyFilePath += xipherPubKeyFileExt
					}
					if err := os.WriteFile(publicKeyFilePath, []byte(pubKeyStr), 0600); err != nil {
						exitOnError(err, jsonFormat)
					}
					if jsonFormat {
						resultMap["publicKeyFile"] = publicKeyFilePath
					} else {
						fmt.Println("Public Key saved to:", color.GreenString(publicKeyFilePath))
					}
				} else {
					if jsonFormat {
						resultMap["publicKey"] = pubKeyStr
					} else {
						fmt.Println("Public Key:", color.GreenString(pubKeyStr))
					}
				}
				if pubKeyUrl != "" {
					if jsonFormat {
						resultMap["publicKeyUrl"] = pubKeyUrl
					} else {
						fmt.Println("Public Key URL:", color.HiCyanString(pubKeyUrl))
					}
				}
				if jsonFormat {
					fmt.Println(toJsonString(resultMap))
				} else {
					fmt.Println("It is completely safe to share this public key with anyone.")
				}
			},
		}
		keygenCmd.Flags().BoolP(ignorePasswordCheckFlag.fields())
		keygenCmd.Flags().StringP(publicKeyFileFlag.fields())
		keygenCmd.Flags().BoolP(autoGenerateSecretKey.fields())
		keygenCmd.Flags().BoolP(quantumSafeFlag.fields())
	}
	return keygenCmd
}
