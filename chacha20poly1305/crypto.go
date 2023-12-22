package chacha20poly1305

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.shib.me/xipher/commons"
)

func (cipher *Cipher) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if compression {
		if data, err = commons.Compress(data); err != nil {
			return nil, err
		}
	}
	return append(nonce, (*cipher.aead).Seal(nil, nonce, data, nil)...), nil
}

func Encrypt(key, data []byte, compression bool) (ciphertext []byte, err error) {
	cipher, err := Get(key)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(data, compression)
}

func (cipher *Cipher) Decrypt(ciphertext []byte, compression bool) (data []byte, err error) {
	if len(ciphertext) < chacha20poly1305.NonceSize {
		return nil, errIncorrectCipherTextSize
	}
	if data, err = (*cipher.aead).Open(nil, ciphertext[:chacha20poly1305.NonceSize], ciphertext[chacha20poly1305.NonceSize:], nil); err != nil {
		return nil, err
	}
	if !compression {
		return
	}
	return commons.Decompress(data)
}

func Decrypt(key, ciphertext []byte, compression bool) (data []byte, err error) {
	cipher, err := Get(key)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(ciphertext, compression)
}
