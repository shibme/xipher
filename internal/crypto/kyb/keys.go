package kyb

import (
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

const (
	// PrivateKeyLength is the length of the key seed.
	PrivateKeyLength = mlkem.SeedSize
	// PublicKeyLength is the length of the Kyber-1024 public key.
	PublicKeyLength = mlkem.EncapsulationKeySize1024
	// CiphertextLength is the length of the Kyber-1024 encapsulated key (ciphertext).
	CiphertextLength = mlkem.CiphertextSize1024
)

var (
	errInvalidPrivateKeyLength = fmt.Errorf("invalid private key lengths [please use %d bytes]", PrivateKeyLength)
	errInvalidPublicKeyLength  = fmt.Errorf("invalid public key lengths [please use %d bytes]", PublicKeyLength)
)

// PrivateKey represents a private key.
type PrivateKey struct {
	seed      []byte
	sk        *mlkem.DecapsulationKey1024
	publicKey *PublicKey
}

// PublicKey represents a public key.
type PublicKey struct {
	pk *mlkem.EncapsulationKey1024
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
	sk, err := mlkem.NewDecapsulationKey1024(keySeed)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		seed: keySeed,
		sk:   sk,
		publicKey: &PublicKey{
			pk: sk.EncapsulationKey(),
		},
	}, nil
}

// PublicKey returns the public key corresponding to the private key. The public key is derived from the private key.
func (privateKey *PrivateKey) PublicKey() (*PublicKey, error) {
	if privateKey.publicKey == nil {
		privateKey.sk.EncapsulationKey()
		privateKey.publicKey = &PublicKey{
			pk: privateKey.sk.EncapsulationKey(),
		}
	}
	return privateKey.publicKey, nil
}

// ParsePublicKey returns the instance of public key for given bytes. Please use exactly 32 bytes.
func ParsePublicKey(keyBytes []byte) (*PublicKey, error) {
	if len(keyBytes) != PublicKeyLength {
		return nil, errInvalidPublicKeyLength
	}
	pk, err := mlkem.NewEncapsulationKey1024(keyBytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		pk: pk,
	}, nil
}

// Bytes returns the bytes of the public key.
func (publicKey *PublicKey) Bytes() []byte {
	return publicKey.pk.Bytes()
}

// Encapsulate performs ML-KEM-1024 encapsulation against the public key.
// It returns the encapsulated key (ciphertext, to be sent to the recipient)
// along with the derived shared secret.
func (publicKey *PublicKey) Encapsulate() (keyEnc, sharedKey []byte, err error) {
	sharedKey, keyEnc = publicKey.pk.Encapsulate()
	return keyEnc, sharedKey, nil
}

// Decapsulate recovers the shared secret from an ML-KEM-1024 encapsulated key using the private key.
func (privateKey *PrivateKey) Decapsulate(keyEnc []byte) (sharedKey []byte, err error) {
	return privateKey.sk.Decapsulate(keyEnc)
}
