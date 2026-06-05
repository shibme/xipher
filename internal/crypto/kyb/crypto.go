package kyb

import (
	"io"

	"xipher.org/xipher/internal/crypto/xcp"
)

// NewEncryptingWriter returns a new WriteCloser that encrypts data with the public key and writes to dst.
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compress bool) (io.WriteCloser, error) {
	encrypter, err := publicKey.getEncrypter()
	if err != nil {
		return nil, err
	}
	if _, err = dst.Write(encrypter.keyEnc); err != nil {
		return nil, err
	}
	return (*encrypter.cipher).NewEncryptingWriter(dst, compress)
}

// NewDecryptingReader returns a new Reader that reads and decrypts data with the private key from src.
func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.Reader, error) {
	keyEnc := make([]byte, ctLength)
	if _, err := io.ReadFull(src, keyEnc); err != nil {
		return nil, err
	}
	sharedKey, err := privateKey.sk.Decapsulate(keyEnc)
	if err != nil {
		return nil, err
	}
	decrypter, err := xcp.New(sharedKey)
	if err != nil {
		return nil, err
	}
	return decrypter.NewDecryptingReader(src)
}
