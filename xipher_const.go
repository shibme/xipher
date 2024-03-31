package xipher

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"dev.shib.me/xipher/internal/asx"
)

const (
	// privateKeyRawLength is the length of a private key when being generated.
	privateKeyRawLength = asx.PrivateKeyLength
	// privateKeyFinalLength is the length of a private key when being exported.
	privateKeyFinalLength = 2 + privateKeyRawLength
	// publicKeyMinLength is the minimum length of a public key.
	publicKeyMinLength = 1 + asx.MinPublicKeyLength

	// Argon2 Default Spec
	argon2Iterations uint8 = 16
	argon2Memory     uint8 = 64
	argon2Threads    uint8 = 1

	kdfParamsLenth = 3
	kdfSaltLength  = 16
	kdfSpecLength  = kdfParamsLenth + kdfSaltLength

	// Key Types
	keyTypeDirect uint8 = 0
	keyTypePwd    uint8 = 1

	// Ciphertext Types
	ctKeyAsymmetric uint8 = 0
	ctPwdAsymmetric uint8 = 1
	ctKeySymmetric  uint8 = 2
	ctPwdSymmetric  uint8 = 3

	xipherVersion uint8 = 0
)

var (
	errGeneratingSalt              = fmt.Errorf("%s: error generating salt", "xipher")
	errInvalidPassword             = fmt.Errorf("%s: invalid password", "xipher")
	errInvalidCiphertext           = fmt.Errorf("%s: invalid ciphertext", "xipher")
	errPrivKeyUnavailableForPwd    = fmt.Errorf("%s: can't derive private key for passwords", "xipher")
	errInvalidPublicKey            = fmt.Errorf("%s: invalid public key", "xipher")
	errInvalidKDFSpec              = fmt.Errorf("%s: invalid kdf spec", "xipher")
	errDecryptionFailedPwdRequired = fmt.Errorf("%s: decryption failed, password required", "xipher")
	errDecryptionFailedKeyRequired = fmt.Errorf("%s: decryption failed, key required", "xipher")
)

var (
	version    = ""
	commitDate = ""
	fullCommit = ""
	releaseURL = ""
	appInfo    *string
)

const (
	website     = "https://dev.shib.me/xipher"
	description = "Xipher is a curated collection of cryptographic primitives put together to perform key/password based asymmetric encryption."
	art         = `
	__  ___       _               
	\ \/ (_)_ __ | |__   ___ _ __ 
	 \  /| | '_ \| '_ \ / _ \ '__|
	 /  \| | |_) | | | |  __/ |   
	/_/\_\_| .__/|_| |_|\___|_|   
	       |_|                    `
)

func VersionInfo() string {
	if appInfo == nil {
		appInfo = new(string)
		var committedAt string
		if builtAtTime, err := time.Parse(time.RFC3339, commitDate); err == nil {
			builtAtLocalTime := builtAtTime.Local()
			committedAt = builtAtLocalTime.Format("02 Jan 2006 03:04:05 PM MST")
		}
		appInfoBuilder := strings.Builder{}
		appInfoBuilder.WriteString(art)
		appInfoBuilder.WriteString("\n")
		appInfoBuilder.WriteString(description)
		appInfoBuilder.WriteString("\n")
		appInfoBuilder.WriteString("-------------------------------------------------")
		appInfoBuilder.WriteString("\n")
		appInfoBuilder.WriteString(fmt.Sprintf("SLV Version  : %s\n", version))
		appInfoBuilder.WriteString(fmt.Sprintf("Built At     : %s\n", committedAt))
		appInfoBuilder.WriteString(fmt.Sprintf("Release      : %s\n", releaseURL))
		appInfoBuilder.WriteString(fmt.Sprintf("Git Commit   : %s\n", fullCommit))
		appInfoBuilder.WriteString(fmt.Sprintf("Web          : %s\n", website))
		appInfoBuilder.WriteString(fmt.Sprintf("Platform     : %s\n", runtime.GOOS+"/"+runtime.GOARCH))
		appInfoBuilder.WriteString(fmt.Sprintf("Go Version   : %s", runtime.Version()))
		*appInfo = appInfoBuilder.String()
	}
	return *appInfo
}
