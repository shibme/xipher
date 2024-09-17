package ecc

import (
	"fmt"
	"io"

	"dev.shib.me/xipher/crypto/xcp"
	"golang.org/x/crypto/curve25519"
)

// NewEncryptingWriter returns a new WriteCloser that encrypts data with the public key and writes to dst.
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compress bool) (io.WriteCloser, error) {
	encrypter, err := publicKey.getEncrypter()
	if err != nil {
		return nil, err
	}
	if _, err = dst.Write(encrypter.ephPubKey); err != nil {
		return nil, fmt.Errorf("%s: encrypter failed to write ephemeral public key", "xipher")
	}
	return (*encrypter.cipher).NewEncryptingWriter(dst, compress)
}

// NewDecryptingReader returns a new Reader that reads and decrypts data with the private key from src.
func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.Reader, error) {
	ephPubKey := make([]byte, KeyLength)
	if _, err := io.ReadFull(src, ephPubKey); err != nil {
		return nil, fmt.Errorf("%s: decrypter failed to read ephemeral public key", "xipher")
	}
	sharedKey, err := curve25519.X25519(*privateKey.key, ephPubKey)
	if err != nil {
		return nil, fmt.Errorf("%s: decrypter failed to generate shared key", "xipher")
	}
	decrypter, err := xcp.New(sharedKey)
	if err != nil {
		return nil, err
	}
	return decrypter.NewDecryptingReader(src)
}
