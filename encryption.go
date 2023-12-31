package xipher

import (
	"bytes"
	"io"

	"gopkg.shib.me/xipher/internal/symmcipher"
)

// EncryptStream encrypts src with the private key treating it as a symmetric key and writes to dst.
func (privateKey *PrivateKey) EncryptStream(dst io.Writer, src io.Reader, compression bool) (err error) {
	if privateKey.isPwdBased() {
		dst.Write([]byte{ctPwdSymmetric})
		dst.Write(privateKey.spec.Bytes())
	} else {
		dst.Write([]byte{ctKeySymmetric})
	}
	if privateKey.symEncrypter == nil {
		if privateKey.symEncrypter, err = symmcipher.New(privateKey.key); err != nil {
			return err
		}
	}
	return privateKey.symEncrypter.Encrypt(dst, src, compression)
}

// Encrypt encrypts data with the private key treating it as a symmetric key.
func (privateKey *PrivateKey) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = privateKey.EncryptStream(&buf, bytes.NewReader(data), compression); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncryptStream encrypts src with the public key and writes to dst.
func (publicKey *PublicKey) EncryptStream(dst io.Writer, src io.Reader, compression bool) (err error) {
	if publicKey.isPwdBased() {
		dst.Write([]byte{ctPwdAsymmetric})
		dst.Write(publicKey.spec.Bytes())
	} else {
		dst.Write([]byte{ctKeyAsymmetric})
	}
	return publicKey.publicKey.Encrypt(dst, src, compression)
}

// Encrypt encrypts data with the public key.
func (publicKey *PublicKey) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = publicKey.EncryptStream(&buf, bytes.NewReader(data), compression); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
