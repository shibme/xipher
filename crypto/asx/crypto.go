package asx

import (
	"fmt"
	"io"
)

// NewEncryptingWriter returns a new WriteCloser that encrypts data with the public key and writes to dst.
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compress bool) (io.WriteCloser, error) {
	if publicKey.ePub != nil {
		if _, err := dst.Write([]byte{algoECC}); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write algorithm", "xipher")
		}
		return publicKey.ePub.NewEncryptingWriter(dst, compress)
	} else if publicKey.kPub != nil {
		if _, err := dst.Write([]byte{algoKyber}); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write algorithm", "xipher")
		}
		return publicKey.kPub.NewEncryptingWriter(dst, compress)
	} else {
		return nil, errInvalidPublicKey
	}
}

// NewDecryptingReader returns a new ReadCloser that reads and decrypts data with the private key from src.
func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.ReadCloser, error) {
	algoBytes := make([]byte, 1)
	if _, err := io.ReadFull(src, algoBytes); err != nil {
		return nil, fmt.Errorf("%s: decrypter failed to read algorithm", "xipher")
	}
	var algo uint8 = algoBytes[0]
	if algo == algoECC {
		eccPrivKey, err := privateKey.getEccPrivKey()
		if err != nil {
			return nil, err
		}
		return eccPrivKey.NewDecryptingReader(src)
	} else if algo == algoKyber {
		kybPrivKey, err := privateKey.getKybPrivKey()
		if err != nil {
			return nil, err
		}
		return kybPrivKey.NewDecryptingReader(src)
	} else {
		return nil, errInvalidAlgorithm
	}
}
