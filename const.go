package xipher

import (
	"errors"
	"strconv"

	"gopkg.shib.me/xipher/chacha20poly1305"
	"gopkg.shib.me/xipher/ecc"
)

const (
	keyLength           = 32
	ciphertextMinLength = chacha20poly1305.CipherTextMinLength
	argon2ParamsLength  = 3
	argon2SaltLength    = 16
	kdfSpecLength       = argon2ParamsLength + argon2SaltLength

	publicKeyMinLength = ecc.KeyLength
	publicKeyMaxLength = publicKeyMinLength + kdfSpecLength

	// Argon2 Default Spec
	argon2Iterations uint8 = 12
	argon2Memory     uint8 = 16
	argon2Threads    uint8 = 1

	pwdSymmetric  byte = 1
	keySymmetric  byte = 2
	pwdAsymmetric byte = 3
	keyAsymmetric byte = 4

	ctMinLenKeySymmetric  = ciphertextMinLength
	ctMinLenPwdSymmetric  = ctMinLenKeySymmetric + kdfSpecLength
	ctMinLenKeyAsymmetric = ctMinLenKeySymmetric + ecc.KeyLength
	ctMinLenPwdAsymmetric = ctMinLenPwdSymmetric + ecc.KeyLength
)

var (
	passwordXipherMap = make(map[string]*PrivateKey)
	keyXipherMap      = make(map[string]*PrivateKey)

	errGeneratingSalt              = errors.New("error generating salt")
	errInvalidPassword             = errors.New("invalid password")
	errIncorrectKeyLength          = errors.New("incorrect key length. requires a key length of " + strconv.Itoa(keyLength) + " bytes")
	errIncorrectCiphertext         = errors.New("incorrect ciphertext")
	errPrivKeyUnavailableForPwd    = errors.New("private is unavailable for passwords")
	errIncorrectKDFSpecLength      = errors.New("incorrect keygen spec length")
	errDecryptionFailedPwdNotFound = errors.New("decryption failed. password not found.")
)
