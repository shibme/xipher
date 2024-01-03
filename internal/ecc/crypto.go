package ecc

import (
	"io"

	"dev.shib.me/xipher/internal/symmcipher"
	"golang.org/x/crypto/curve25519"
)

// NewEncryptingWriter returns a new WriteCloser that encrypts data with the public key and writes to dst.
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compression bool) (io.WriteCloser, error) {
	encrypter, err := publicKey.getEncrypter()
	if err != nil {
		return nil, err
	}
	if _, err = dst.Write(encrypter.ephPubKey); err != nil {
		return nil, err
	}
	return (*encrypter.cipher).NewEncryptingWriter(dst, compression)
}

// NewDecryptingReader returns a new ReadCloser that reads and decrypts data with the private key from src.
func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.ReadCloser, error) {
	ephPubKey := make([]byte, KeyLength)
	if _, err := io.ReadFull(src, ephPubKey); err != nil {
		return nil, err
	}
	sharedKey, err := curve25519.X25519(*privateKey.key, ephPubKey)
	if err != nil {
		return nil, err
	}
	decrypter, err := symmcipher.New(sharedKey)
	if err != nil {
		return nil, err
	}
	return decrypter.NewDecryptingReader(src)
}
