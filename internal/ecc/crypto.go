package ecc

import (
	"bytes"
	"io"

	"golang.org/x/crypto/curve25519"
	"gopkg.shib.me/xipher/internal/symmcipher"
)

// Encrypt encrypts src with the public key and writes to dst.
func (publicKey *PublicKey) Encrypt(dst io.Writer, src io.Reader, compression bool) (err error) {
	encrypter, err := publicKey.getEncrypter()
	if err != nil {
		return err
	}
	if _, err = dst.Write(encrypter.ephPubKey); err != nil {
		return err
	}
	return (*encrypter.cipher).Encrypt(dst, src, compression)
}

// EncryptBytes encrypts data with the public key.
func (publicKey *PublicKey) EncryptBytes(data []byte, compression bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = publicKey.Encrypt(&buf, bytes.NewReader(data), compression); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext with the private key and writes to dst.
func (privateKey *PrivateKey) Decrypt(dst io.Writer, src io.Reader) error {
	ephPubKey := make([]byte, KeyLength)
	if _, err := io.ReadFull(src, ephPubKey); err != nil {
		return err
	}
	sharedKey, err := curve25519.X25519(*privateKey.key, ephPubKey)
	if err != nil {
		return err
	}
	return symmcipher.Decrypt(dst, src, sharedKey)
}

// DecryptBytes decrypts ciphertext with the private key.
func (privateKey *PrivateKey) DecryptBytes(ciphertext []byte) (data []byte, err error) {
	var buf bytes.Buffer
	if err = privateKey.Decrypt(&buf, bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
