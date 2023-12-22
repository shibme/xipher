package xipher

import (
	"crypto/rand"

	"gopkg.shib.me/xipher/argon2"
	"gopkg.shib.me/xipher/chacha20poly1305"
	"gopkg.shib.me/xipher/commons"
	"gopkg.shib.me/xipher/ecc"
)

type PrivateKey struct {
	password           *[]byte
	kdfSpec            *[]byte
	key                *[]byte
	symmetricEncrypter *chacha20poly1305.Cipher
	publicKey          *PublicKey
	pwdSpecKeyMap      map[string][]byte
}

func keyFromArgonSpecBytes(password, kdfSpec []byte) ([]byte, error) {
	if len(kdfSpec) != kdfSpecLength {
		return nil, errIncorrectKDFSpecLength
	}
	return keyFromArgonSpec(password, kdfSpec[3:], kdfSpec[0], kdfSpec[1], kdfSpec[2]), nil
}

func argonSpecToBytes(iterations, memory, threads uint8, salt []byte) []byte {
	return append([]byte{iterations, memory, threads}, salt...)
}

func keyFromArgonSpec(password, salt []byte, iterations, memory, threads uint8) []byte {
	return argon2.DeriveKey(password).Length(keyLength).
		Iterations(uint32(iterations)).Memory(uint32(memory)).
		Threads(threads).DeriveWithSalt(salt)
}

func NewPrivateKeyForPassword(password []byte) (*PrivateKey, error) {
	return NewPrivateKeyForPasswordWithSpec(password, argon2Iterations, argon2Memory, argon2Threads)
}

func NewPrivateKeyForPasswordWithSpec(password []byte, iterations, memory, threads uint8) (*PrivateKey, error) {
	if len(password) == 0 {
		return nil, errInvalidPassword
	}
	if iterations == 0 {
		iterations = argon2Iterations
	}
	if memory == 0 {
		memory = argon2Memory
	}
	if threads == 0 {
		threads = argon2Threads
	}
	privateKey := passwordXipherMap[string(password)]
	if privateKey == nil {
		salt := make([]byte, argon2SaltLength)
		if _, err := rand.Read(salt); err != nil {
			return nil, errGeneratingSalt
		}
		key := keyFromArgonSpec(password, salt, iterations, memory, threads)
		kdfSpec := argonSpecToBytes(iterations, memory, threads, salt)
		privateKey = &PrivateKey{
			password: &password,
			kdfSpec:  &kdfSpec,
			key:      &key,
		}
		passwordXipherMap[string(password)] = privateKey
		privateKey.pwdSpecKeyMap = make(map[string][]byte)
		privateKey.pwdSpecKeyMap[string(kdfSpec)] = key
	}
	return privateKey, nil
}

func GetPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != keyLength {
		return nil, errIncorrectKeyLength
	}
	privateKey := keyXipherMap[string(key)]
	if privateKey == nil {
		privateKey = &PrivateKey{
			key: &key,
		}
		keyXipherMap[string(key)] = privateKey
	}
	return privateKey, nil
}

func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	privateKey := &PrivateKey{
		key: &key,
	}
	keyXipherMap[string(key)] = privateKey
	return privateKey, nil
}

func (privateKey *PrivateKey) Bytes() ([]byte, error) {
	if privateKey.kdfSpec != nil {
		return nil, errPrivKeyUnavailableForPwd
	}
	return *privateKey.key, nil
}

func (privateKey *PrivateKey) PublicKey() (*PublicKey, error) {
	if privateKey.publicKey == nil {
		eccPrivKey, err := ecc.GetPrivateKey(*privateKey.key)
		if err != nil {
			return nil, err
		}
		eccPubKey, err := eccPrivKey.PublicKey()
		if err != nil {
			return nil, err
		}
		privateKey.publicKey = &PublicKey{
			publicKey: eccPubKey,
			kdfSpec:   privateKey.kdfSpec,
		}
	}
	return privateKey.publicKey, nil
}

type PublicKey struct {
	publicKey *ecc.PublicKey
	kdfSpec   *[]byte
}

func GetPublicKey(key []byte) (*PublicKey, error) {
	if publicKeyMinLength <= len(key) && publicKeyMaxLength != len(key) {
		return nil, errIncorrectKeyLength
	}
	eccPubKey, err := ecc.GetPublicKey(key[:keyLength])
	if err != nil {
		return nil, err
	}
	publicKey := &PublicKey{
		publicKey: eccPubKey,
	}
	if len(key) == publicKeyMaxLength {
		publicKey.kdfSpec = commons.ByteSlicePtr(key[keyLength:])
	}
	return publicKey, nil
}

func (publicKey *PublicKey) Bytes() []byte {
	if publicKey.kdfSpec != nil {
		return append(*publicKey.kdfSpec, publicKey.publicKey.Bytes()...)
	}
	return publicKey.publicKey.Bytes()
}
