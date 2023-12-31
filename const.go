package xipher

import (
	"errors"
	"strconv"

	"gopkg.shib.me/xipher/internal/ecc"
	"gopkg.shib.me/xipher/internal/symmcipher"
)

const (
	ciphertextMinLength = symmcipher.CipherTextMinLength
	cipherKeyLength     = 32
	PublicKeyLength     = cipherKeyLength + specLength

	// Xipher Types
	// typeKey byte = 0
	// typePwd byte = 1

	// Ciphertext Types
	ctKeySymmetric  byte = 1
	ctKeyAsymmetric byte = 2
	ctPwdSymmetric  byte = 3
	ctPwdAsymmetric byte = 4

	// Argon2 Default Spec
	argon2Iterations uint8 = 32
	argon2Memory     uint8 = 32
	argon2Threads    uint8 = 1

	ctMinLenKeySymmetric  = ciphertextMinLength
	ctMinLenPwdSymmetric  = ctMinLenKeySymmetric + specLength
	ctMinLenKeyAsymmetric = ctMinLenKeySymmetric + ecc.KeyLength
	ctMinLenPwdAsymmetric = ctMinLenPwdSymmetric + ecc.KeyLength
)

var (
	pwdXipherMap = make(map[string]*PrivateKey)
	keyXipherMap = make(map[string]*PrivateKey)

	errGeneratingSalt              = errors.New("error generating salt")
	errInvalidPassword             = errors.New("invalid password")
	errIncorrectKeyLength          = errors.New("incorrect key length. requires a key length of " + strconv.Itoa(cipherKeyLength) + " bytes")
	errInvalidCiphertext           = errors.New("invalid ciphertext")
	errPrivKeyUnavailableForPwd    = errors.New("private is unavailable for passwords")
	errInvalidKDFSpec              = errors.New("invalid kdf spec")
	errUnsupportedDecryption       = errors.New("unsupported decryption")
	errDecryptionFailedPwdNotFound = errors.New("decryption failed. password not found.")
	errInvalidPublicKey            = errors.New("invalid public key")
)
