package symmcipher

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLength           = chacha20poly1305.KeySize
	CipherTextMinLength = chacha20poly1305.NonceSize + chacha20poly1305.Overhead
	ptBlockSize         = 64 * 1024
	ctBlockSize         = ptBlockSize + chacha20poly1305.Overhead
)

var cipherMap map[string]*Cipher = make(map[string]*Cipher)

// Cipher is a wrapper around the AEAD interface from the golang.org/x/crypto/chacha20poly1305 package.
type Cipher struct {
	aead *cipher.AEAD
}

// New returns a new Cipher instance. If a Cipher instance with the same key has already been created, it will be returned instead.
func New(key []byte) (*Cipher, error) {
	cipher := cipherMap[string(key)]
	if cipher == nil {
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		cipher = &Cipher{
			aead: &aead,
		}
		cipherMap[string(key)] = cipher
	}
	return cipher, nil
}
