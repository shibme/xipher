package xipher

import (
	"fmt"

	"dev.shib.me/xipher/internal/asx"
)

const (

	// secretKeyBaseLength is the length of a secret key when being generated.
	secretKeyBaseLength = asx.PrivateKeyLength
	// secretKeyLength is the length of a private key when being exported.
	secretKeyLength = secretKeyBaseLength + 2
	// publicKeyMinLength is the minimum length of a public key.
	publicKeyMinLength = asx.MinPublicKeyLength + 1 // +1 for the key type

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

	keyVersion uint8 = 0
)

var (
	errGeneratingSalt              = fmt.Errorf("%s: error generating salt", "xipher")
	errInvalidPassword             = fmt.Errorf("%s: invalid password", "xipher")
	errInvalidCiphertext           = fmt.Errorf("%s: invalid ciphertext", "xipher")
	errSecretKeyUnavailableForPwd  = fmt.Errorf("%s: can't derive secret key for passwords", "xipher")
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
