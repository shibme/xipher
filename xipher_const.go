package xipher

import (
	"fmt"

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
	Version = "dev"

	errGeneratingSalt              = fmt.Errorf("%s: error generating salt", "xipher")
	errInvalidPassword             = fmt.Errorf("%s: invalid password", "xipher")
	errInvalidCiphertext           = fmt.Errorf("%s: invalid ciphertext", "xipher")
	errPrivKeyUnavailableForPwd    = fmt.Errorf("%s: can't derive private key for passwords", "xipher")
	errInvalidPublicKey            = fmt.Errorf("%s: invalid public key", "xipher")
	errInvalidKDFSpec              = fmt.Errorf("%s: invalid kdf spec", "xipher")
	errDecryptionFailedPwdRequired = fmt.Errorf("%s: decryption failed, password required", "xipher")
	errDecryptionFailedKeyRequired = fmt.Errorf("%s: decryption failed, key required", "xipher")
)
