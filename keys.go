package xipher

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"

	"dev.shib.me/xipher/internal/ecc"
	"dev.shib.me/xipher/internal/symmcipher"
)

type PrivateKey struct {
	password     *[]byte
	spec         *kdfSpec
	key          []byte
	symEncrypter *symmcipher.Cipher
	publicKey    *PublicKey
	specKeyMap   map[string][]byte
}

// NewPrivateKeyForPassword creates a new private key for the given password.
func NewPrivateKeyForPassword(password []byte) (*PrivateKey, error) {
	spec, err := newSpec()
	if err != nil {
		return nil, err
	}
	return newPrivateKeyForPwdAndSpec(password, spec)
}

// NewPrivateKeyForPasswordAndSpec creates a new private key for the given password and kdf spec.
func NewPrivateKeyForPasswordAndSpec(password []byte, iterations, memory, threads uint8) (*PrivateKey, error) {
	spec, err := newSpec()
	if err != nil {
		return nil, err
	}
	spec.setIterations(iterations).setMemory(memory).setThreads(threads)
	return newPrivateKeyForPwdAndSpec(password, spec)
}

func newPrivateKeyForPwdAndSpec(password []byte, spec *kdfSpec) (*PrivateKey, error) {
	if len(password) == 0 {
		return nil, errInvalidPassword
	}
	privateKey := xipherPwdMap[string(password)]
	if privateKey == nil {
		privateKey = &PrivateKey{
			password: &password,
			spec:     spec,
		}
		privateKey.key = spec.getCipherKey(*privateKey.password)
		xipherPwdMap[string(*privateKey.password)] = privateKey
		privateKey.specKeyMap = make(map[string][]byte)
		privateKey.specKeyMap[string(privateKey.spec.bytes())] = privateKey.key
	}
	return privateKey, nil
}

// NewPrivateKey creates a new random private key.
func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, cipherKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	privateKey := &PrivateKey{
		key: key,
	}
	xipherKeyMap[string(key)] = privateKey
	return privateKey, nil
}

// ParsePrivateKey parses the given bytes and returns a corresponding private key. the given bytes must be 32 bytes long.
func ParsePrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != PrivateKeyLength {
		return nil, fmt.Errorf("%s: invalid private key length: expected %d, got %d", "xipher", PrivateKeyLength, len(key))
	}
	privateKey := xipherKeyMap[string(key)]
	if privateKey == nil {
		privateKey = &PrivateKey{
			key: key,
		}
		xipherKeyMap[string(key)] = privateKey
	}
	return privateKey, nil
}

func (privateKey *PrivateKey) isPwdBased() bool {
	return privateKey.password != nil && privateKey.spec != nil
}

// Bytes returns the private key as bytes only if it is not password based.
func (privateKey *PrivateKey) Bytes() ([]byte, error) {
	if privateKey.password != nil || privateKey.spec != nil {
		return nil, errPrivKeyUnavailableForPwd
	}
	return privateKey.key, nil
}

// PublicKey returns the public key corresponding to the private key.
func (privateKey *PrivateKey) PublicKey() (*PublicKey, error) {
	if privateKey.publicKey == nil {
		eccPrivKey, err := ecc.GetPrivateKey(privateKey.key)
		if err != nil {
			return nil, err
		}
		eccPubKey, err := eccPrivKey.PublicKey()
		if err != nil {
			return nil, err
		}
		privateKey.publicKey = &PublicKey{
			publicKey: eccPubKey,
			spec:      privateKey.spec,
		}
	}
	return privateKey.publicKey, nil
}

type PublicKey struct {
	publicKey *ecc.PublicKey
	spec      *kdfSpec
}

// ParsePublicKey parses the given bytes and returns a corresponding public key. the given bytes must be 51 bytes long.
func ParsePublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) != PublicKeyLength {
		return nil, fmt.Errorf("%s: invalid public key length: expected %d, got %d", "xipher", PublicKeyLength, len(pubKeyBytes))
	}
	keyBytes := pubKeyBytes[:cipherKeyLength]
	eccPubKey, err := ecc.GetPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	publicKey := &PublicKey{
		publicKey: eccPubKey,
	}
	specBytes := pubKeyBytes[cipherKeyLength:]
	if specBytes[0] == zero {
		sum := sha1.Sum(keyBytes)
		if !bytes.Equal(sum[:kdfSpecLength-1], specBytes[1:]) {
			return nil, errInvalidPublicKey
		}
	} else {
		publicKey.spec, err = parseKdfSpec(specBytes)
		if err != nil {
			return nil, err
		}
	}
	return publicKey, nil
}

func (publicKey *PublicKey) isPwdBased() bool {
	return publicKey.spec != nil
}

// Bytes returns the public key as bytes.
func (publicKey *PublicKey) Bytes() []byte {
	pubKeyBytes := publicKey.publicKey.Bytes()
	if publicKey.spec != nil {
		return append(pubKeyBytes, publicKey.spec.bytes()...)
	} else {
		sum := sha1.Sum(pubKeyBytes)
		return append(pubKeyBytes, append([]byte{zero}, sum[:kdfSpecLength-1]...)...)
	}
}
