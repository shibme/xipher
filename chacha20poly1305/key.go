package chacha20poly1305

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
	aead *cipher.AEAD
}

func Get(key []byte) (*Cipher, error) {
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
