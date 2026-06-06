// Package hyb implements a hybrid key encapsulation mechanism that combines
// classical X25519 (ECC) with post-quantum ML-KEM-1024 (Kyber). The two shared
// secrets are bound together with an X-Wing-style HKDF combiner so that the
// derived symmetric key remains secure as long as either primitive holds.
//
// This construction is X-Wing-style but is NOT RFC X-Wing: it targets
// ML-KEM-1024 (rather than ML-KEM-768) and uses HKDF-SHA256 (rather than
// SHA3-256). It carries its own domain-separation label accordingly.
package hyb

import (
	"fmt"

	"xipher.org/xipher/internal/crypto/ecc"
	"xipher.org/xipher/internal/crypto/kyb"
)

const (
	// PublicKeyLength is the length of the hybrid public key: the X25519 public
	// key concatenated with the ML-KEM-1024 public key.
	PublicKeyLength = ecc.KeyLength + kyb.PublicKeyLength
)

var errInvalidPublicKeyLength = fmt.Errorf("invalid public key length [please use %d bytes]", PublicKeyLength)

// PublicKey represents a hybrid public key combining ECC and Kyber public keys.
type PublicKey struct {
	ePub *ecc.PublicKey
	kPub *kyb.PublicKey
}

// PrivateKey represents a hybrid private key combining ECC and Kyber private keys.
type PrivateKey struct {
	eccPriv *ecc.PrivateKey
	kybPriv *kyb.PrivateKey
}

// NewPublicKey assembles a hybrid public key from its ECC and Kyber components.
func NewPublicKey(ePub *ecc.PublicKey, kPub *kyb.PublicKey) *PublicKey {
	return &PublicKey{
		ePub: ePub,
		kPub: kPub,
	}
}

// NewPrivateKey assembles a hybrid private key from its ECC and Kyber components.
func NewPrivateKey(eccPriv *ecc.PrivateKey, kybPriv *kyb.PrivateKey) *PrivateKey {
	return &PrivateKey{
		eccPriv: eccPriv,
		kybPriv: kybPriv,
	}
}

// Bytes returns the hybrid public key as the X25519 public key followed by the
// ML-KEM-1024 public key.
func (publicKey *PublicKey) Bytes() []byte {
	return append(publicKey.ePub.Bytes(), publicKey.kPub.Bytes()...)
}

// ParsePublicKey parses a hybrid public key from its byte representation.
// The input must be exactly PublicKeyLength bytes: the X25519 public key
// followed by the ML-KEM-1024 public key.
func ParsePublicKey(key []byte) (*PublicKey, error) {
	if len(key) != PublicKeyLength {
		return nil, errInvalidPublicKeyLength
	}
	ePub, err := ecc.ParsePublicKey(key[:ecc.KeyLength])
	if err != nil {
		return nil, err
	}
	kPub, err := kyb.ParsePublicKey(key[ecc.KeyLength:])
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		ePub: ePub,
		kPub: kPub,
	}, nil
}
