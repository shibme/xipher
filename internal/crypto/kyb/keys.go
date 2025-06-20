package kyb

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"xipher.org/xipher/internal/crypto/xcp"
)

const (
	// PrivateKeyLength is the length of the key seed.
	PrivateKeyLength = kyber1024.KeySeedSize
	// PublicKeyLength is the length of the Kyber-1024 public key.
	PublicKeyLength = kyber1024.PublicKeySize
	ctLength        = kyber1024.CiphertextSize
)

var (
	errInvalidPrivateKeyLength = fmt.Errorf("invalid private key lengths [please use %d bytes]", PrivateKeyLength)
	errInvalidPublicKeyLength  = fmt.Errorf("invalid public key lengths [please use %d bytes]", PublicKeyLength)
)

// PrivateKey represents a private key.
type PrivateKey struct {
	seed      []byte
	sk        *kyber1024.PrivateKey
	publicKey *PublicKey
}

// PublicKey represents a public key.
type PublicKey struct {
	pk        *kyber1024.PublicKey
	encrypter *encrypter
}

type encrypter struct {
	keyEnc []byte
	cipher *xcp.SymmetricCipher
}

// Bytes returns the bytes of the private key.
func (privateKey *PrivateKey) Bytes() []byte {
	return privateKey.seed
}

// NewPrivateKey generates a new random private key.
func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, PrivateKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return NewPrivateKeyForSeed(key)
}

// NewPrivateKeyForSeed returns the instance private key for given bytes. Please use exactly 64 bytes.
func NewPrivateKeyForSeed(keySeed []byte) (*PrivateKey, error) {
	if len(keySeed) != PrivateKeyLength {
		return nil, errInvalidPrivateKeyLength
	}
	pk, sk := kyber1024.NewKeyFromSeed(keySeed)
	return &PrivateKey{
		seed: keySeed,
		sk:   sk,
		publicKey: &PublicKey{
			pk: pk,
		},
	}, nil
}

// PublicKey returns the public key corresponding to the private key. The public key is derived from the private key.
func (privateKey *PrivateKey) PublicKey() (*PublicKey, error) {
	if privateKey.publicKey == nil {
		privateKey.sk.Public()
		privateKey.publicKey = &PublicKey{
			pk: privateKey.sk.Public().(*kyber1024.PublicKey),
		}
	}
	return privateKey.publicKey, nil
}

// ParsePublicKey returns the instance of public key for given bytes. Please use exactly 32 bytes.
func ParsePublicKey(keyBytes []byte) (*PublicKey, error) {
	if len(keyBytes) != PublicKeyLength {
		return nil, errInvalidPublicKeyLength
	}
	pk, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		pk: pk.(*kyber1024.PublicKey),
	}, nil
}

// Bytes returns the bytes of the public key.
func (publicKey *PublicKey) Bytes() ([]byte, error) {
	return publicKey.pk.MarshalBinary()
}

func (publicKey *PublicKey) getEncrypter() (*encrypter, error) {
	if publicKey.encrypter == nil {
		keyEnc, sharedKey, err := kyber1024.Scheme().Encapsulate(publicKey.pk)
		if err != nil {
			return nil, err
		}
		cipher, err := xcp.New(sharedKey)
		if err != nil {
			return nil, err
		}
		publicKey.encrypter = &encrypter{
			keyEnc: keyEnc,
			cipher: cipher,
		}
	}
	return publicKey.encrypter, nil
}
