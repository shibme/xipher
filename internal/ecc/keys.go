package ecc

import (
	"crypto/rand"
	"fmt"

	"dev.shib.me/xipher/internal/symmcipher"
	"golang.org/x/crypto/curve25519"
)

const (
	// KeyLength is the length of the ECC key.
	KeyLength = curve25519.ScalarSize
)

var (
	errInvalidKeyLength = fmt.Errorf("xipher: invalid key lengths [please use %d bytes]", KeyLength)

	privateKeyMap map[string]*PrivateKey = make(map[string]*PrivateKey)
	publicKeyMap  map[string]*PublicKey  = make(map[string]*PublicKey)
)

// PrivateKey represents a private key.
type PrivateKey struct {
	key       *[]byte
	publicKey *PublicKey
}

// PublicKey represents a public key.
type PublicKey struct {
	key       *[]byte
	encrypter *encrypter
}

type encrypter struct {
	ephPubKey []byte
	cipher    *symmcipher.Cipher
}

// Bytes returns the bytes of the private key.
func (privateKey *PrivateKey) Bytes() []byte {
	return *privateKey.key
}

// NewPrivateKey generates a new random private key.
func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return GetPrivateKey(key)
}

// GetPrivateKey returns the instance private key for given bytes. Please use exactly 32 bytes.
func GetPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != curve25519.ScalarSize {
		return nil, errInvalidKeyLength
	}
	privateKey := privateKeyMap[string(key)]
	if privateKey == nil {
		privateKey = &PrivateKey{
			key: &key,
		}
		privateKeyMap[string(key)] = privateKey
	}
	return privateKey, nil
}

// PublicKey returns the public key corresponding to the private key. The public key is derived from the private key.
func (privateKey *PrivateKey) PublicKey() (*PublicKey, error) {
	if privateKey.publicKey == nil {
		key, err := curve25519.X25519(*privateKey.key, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		pubKey := publicKeyMap[string(key)]
		if pubKey == nil {
			pubKey = &PublicKey{
				key: &key,
			}
			publicKeyMap[string(key)] = pubKey
		}
		privateKey.publicKey = pubKey
	}
	return privateKey.publicKey, nil
}

// GetPublicKey returns the instance of public key for given bytes. Please use exactly 32 bytes.
func GetPublicKey(key []byte) (*PublicKey, error) {
	if len(key) != curve25519.ScalarSize {
		return nil, errInvalidKeyLength
	}
	publicKey := publicKeyMap[string(key)]
	if publicKey == nil {
		publicKey = &PublicKey{
			key: &key,
		}
		publicKeyMap[string(key)] = publicKey
	}
	return publicKey, nil
}

// Bytes returns the bytes of the public key.
func (publicKey *PublicKey) Bytes() []byte {
	return *publicKey.key
}

func (publicKey *PublicKey) getEncrypter() (*encrypter, error) {
	if publicKey.encrypter == nil {
		ephPrivKey := make([]byte, curve25519.ScalarSize)
		if _, err := rand.Read(ephPrivKey); err != nil {
			return nil, err
		}
		ephPubKey, err := curve25519.X25519(ephPrivKey, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		sharedKey, err := curve25519.X25519(ephPrivKey, *publicKey.key)
		if err != nil {
			return nil, err
		}
		cipher, err := symmcipher.New(sharedKey)
		if err != nil {
			return nil, err
		}
		publicKey.encrypter = &encrypter{
			ephPubKey: ephPubKey,
			cipher:    cipher,
		}
	}
	return publicKey.encrypter, nil
}
