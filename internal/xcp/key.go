package xcp

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLength           = chacha20poly1305.KeySize
	nonceLength         = chacha20poly1305.NonceSizeX
	CipherTextMinLength = nonceLength + chacha20poly1305.Overhead
	ptBlockSize         = 64 * 1024
	ctBlockSize         = ptBlockSize + chacha20poly1305.Overhead
)

// SymmetricCipher is a wrapper around the AEAD interface from the golang.org/x/crypto/chacha20poly1305 package.
type SymmetricCipher struct {
	aead *cipher.AEAD
}

// New returns a new Cipher instance. If a Cipher instance with the same key has already been created, it will be returned instead.
func New(key []byte) (*SymmetricCipher, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new symmetric cipher", "xipher")
	}
	return &SymmetricCipher{
		aead: &aead,
	}, nil
}
