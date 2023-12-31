package xipher

import (
	"errors"

	"gopkg.shib.me/xipher/internal/symmcipher"
)

const (
	ciphertextMinLength = symmcipher.CipherTextMinLength
	cipherKeyLength     = 32

	// PrivateKeyLength is the length of a private key.
	PrivateKeyLength = cipherKeyLength
	// PublicKeyLength is the length of a public key.
	PublicKeyLength = cipherKeyLength + kdfSpecLength

	// Ciphertext Types
	ctKeySymmetric  byte = 1
	ctKeyAsymmetric byte = 2
	ctPwdSymmetric  byte = 3
	ctPwdAsymmetric byte = 4

	// Argon2 Default Spec
	argon2Iterations uint8 = 32
	argon2Memory     uint8 = 32
	argon2Threads    uint8 = 1

	kdfParamsLenth = 3
	kdfSaltLength  = 16
	kdfSpecLength  = kdfParamsLenth + kdfSaltLength
)

var (
	pwdXipherMap = make(map[string]*PrivateKey)
	keyXipherMap = make(map[string]*PrivateKey)

	errGeneratingSalt           = errors.New("error generating salt")
	errInvalidPassword          = errors.New("invalid password")
	errInvalidCiphertext        = errors.New("invalid ciphertext")
	errPrivKeyUnavailableForPwd = errors.New("private is unavailable for passwords")
	errInvalidKDFSpec           = errors.New("invalid kdf spec")
)
