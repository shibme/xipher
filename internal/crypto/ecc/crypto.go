package ecc

import (
	"io"

	"xipher.org/xipher/internal/crypto/xcp"
)

// NewEncryptingWriter returns a new WriteCloser that encrypts data with the public key and writes to dst.
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compress bool) (io.WriteCloser, error) {
	ephPubKey, sharedKey, err := publicKey.Encapsulate()
	if err != nil {
		return nil, err
	}
	if _, err = dst.Write(ephPubKey); err != nil {
		return nil, err
	}
	cipher, err := xcp.New(sharedKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewEncryptingWriter(dst, compress)
}

// NewDecryptingReader returns a new Reader that reads and decrypts data with the private key from src.
func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.Reader, error) {
	ephPubKey := make([]byte, KeyLength)
	if _, err := io.ReadFull(src, ephPubKey); err != nil {
		return nil, err
	}
	sharedKey, err := privateKey.Decapsulate(ephPubKey)
	if err != nil {
		return nil, err
	}
	decrypter, err := xcp.New(sharedKey)
	if err != nil {
		return nil, err
	}
	return decrypter.NewDecryptingReader(src)
}
