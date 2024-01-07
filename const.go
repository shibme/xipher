package xipher

import (
	"fmt"

	"dev.shib.me/xipher/internal/symcipher"
)

const (
	cipherKeyLength = 32

	// PrivateKeyLength is the length of a private key.
	PrivateKeyLength = cipherKeyLength
	// PublicKeyLength is the length of a public key.
	PublicKeyLength = cipherKeyLength + kdfSpecLength
	// CipherTextMinLength is the minimum length of a ciphertext.
	CipherTextMinLength = symcipher.CipherTextMinLength

	// Ciphertext Types
	ctKeySymmetric  byte = 1
	ctKeyAsymmetric byte = 2
	ctPwdSymmetric  byte = 3
	ctPwdAsymmetric byte = 4

	// Argon2 Default Spec
	argon2Iterations uint8 = 16
	argon2Memory     uint8 = 64
	argon2Threads    uint8 = 1

	kdfParamsLenth = 3
	kdfSaltLength  = 16
	kdfSpecLength  = kdfParamsLenth + kdfSaltLength

	zero byte = 0
)

var (
	Version = "dev"

	errGeneratingSalt              = fmt.Errorf("%s: error generating salt", "xipher")
	errInvalidPassword             = fmt.Errorf("%s: invalid password", "xipher")
	errInvalidCiphertext           = fmt.Errorf("%s: invalid ciphertext", "xipher")
	errPrivKeyUnavailableForPwd    = fmt.Errorf("%s: private is unavailable for passwords", "xipher")
	errInvalidPublicKey            = fmt.Errorf("%s: invalid public key", "xipher")
	errInvalidKDFSpec              = fmt.Errorf("%s: invalid kdf spec", "xipher")
	errDecryptionFailedPwdRequired = fmt.Errorf("%s: decryption failed, password required", "xipher")
	errDecryptionFailedKeyRequired = fmt.Errorf("%s: decryption failed, key required", "xipher")
)
