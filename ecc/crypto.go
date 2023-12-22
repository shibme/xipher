package ecc

import (
	"golang.org/x/crypto/curve25519"
	"gopkg.shib.me/xipher/chacha20poly1305"
)

// Encrypt encrypts data with the public key.
func (publicKey *PublicKey) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	encrypter, err := publicKey.getEncrypter()
	if err != nil {
		return nil, err
	}
	if ciphertext, err = (*encrypter.cipher).Encrypt(data, compression); err != nil {
		return nil, err
	}
	return append(encrypter.ephPubKey, ciphertext...), nil
}

// Decrypt decrypts ciphertext with the private key.
func (privateKey *PrivateKey) Decrypt(ciphertext []byte, compression bool) (data []byte, err error) {
	sharedKey, err := curve25519.X25519(*privateKey.key, ciphertext[:curve25519.ScalarSize])
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.Decrypt(sharedKey, ciphertext[curve25519.ScalarSize:], compression)
}
