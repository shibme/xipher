package xipher

import (
	"fmt"

	"dev.shib.me/xipher/internal/xcp"
)

const (
	keyLength = 32

	// PrivateKeyMinLength is the minimum length of a private key.
	PrivateKeyMinLength = 1 + keyLength
	// PublicKeyMinLength is the minimum length of a public key.
	PublicKeyMinLength = 1 + keyLength
	// CipherTextMinLength is the minimum length of a ciphertext.
	CipherTextMinLength = xcp.CipherTextMinLength

	// Argon2 Default Spec
	argon2Iterations uint8 = 16
	argon2Memory     uint8 = 64
	argon2Threads    uint8 = 1

	kdfParamsLenth = 3
	kdfSaltLength  = 16
	kdfSpecLength  = kdfParamsLenth + kdfSaltLength

	// Key Types
	keyTypeEccDirect uint8 = 0
	keyTypeEccPwd    uint8 = 1
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
