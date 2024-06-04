package kyb

import (
	"fmt"
	"io"

	"dev.shib.me/xipher/internal/xcp"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

// NewEncryptingWriter returns a new WriteCloser that encrypts data with the public key and writes to dst.
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compression bool) (io.WriteCloser, error) {
	encrypter, err := publicKey.getEncrypter()
	if err != nil {
		return nil, err
	}
	if _, err = dst.Write(encrypter.keyEnc); err != nil {
		return nil, fmt.Errorf("%s: encrypter failed to write encapsulated key", "xipher")
	}
	return (*encrypter.cipher).NewEncryptingWriter(dst, compression)
}

// NewDecryptingReader returns a new ReadCloser that reads and decrypts data with the private key from src.
func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.ReadCloser, error) {
	keyEnc := make([]byte, ctLength)
	if _, err := io.ReadFull(src, keyEnc); err != nil {
		return nil, fmt.Errorf("%s: decrypter failed to read encapsulated key", "xipher")
	}
	sharedKey, err := kyber1024.Scheme().Decapsulate(privateKey.sk, keyEnc)
	if err != nil {
		return nil, fmt.Errorf("%s: decrypter failed to generate shared key", "xipher")
	}
	decrypter, err := xcp.New(sharedKey)
	if err != nil {
		return nil, err
	}
	return decrypter.NewDecryptingReader(src)
}
