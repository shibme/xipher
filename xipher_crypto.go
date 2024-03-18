package xipher

import (
	"bytes"
	"crypto/sha256"
	"io"

	"dev.shib.me/xipher/internal/asx"
	"dev.shib.me/xipher/internal/xcp"
)

func newVariableKeySymmCipher(key []byte) (*xcp.SymmetricCipher, error) {
	if len(key) == privateKeyRawLength {
		keySum := sha256.Sum256(key)
		key = keySum[:]
	}
	return xcp.New(key)
}

func (privateKey *PrivateKey) NewEncryptingWriter(dst io.Writer, compression bool) (writer io.WriteCloser, err error) {
	if isPwdBased(privateKey.keyType) {
		if _, err := dst.Write([]byte{ctPwdSymmetric}); err != nil {
			return nil, err
		}
		if _, err := dst.Write(privateKey.spec.bytes()); err != nil {
			return nil, err
		}
	} else {
		if _, err := dst.Write([]byte{ctKeySymmetric}); err != nil {
			return nil, err
		}
	}
	if privateKey.symmCipher == nil {
		if privateKey.symmCipher, err = newVariableKeySymmCipher(privateKey.key); err != nil {
			return nil, err
		}
	}
	return privateKey.symmCipher.NewEncryptingWriter(dst, compression)
}

// EncryptStream encrypts src with the private key treating it as a symmetric key and writes to dst.
func (privateKey *PrivateKey) EncryptStream(dst io.Writer, src io.Reader, compression bool) (err error) {
	encryptedWriter, err := privateKey.NewEncryptingWriter(dst, compression)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptedWriter, src); err != nil {
		return err
	}
	return encryptedWriter.Close()
}

// Encrypt encrypts data with the private key treating it as a symmetric key.
func (privateKey *PrivateKey) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = privateKey.EncryptStream(&buf, bytes.NewReader(data), compression); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compression bool) (writer io.WriteCloser, err error) {
	if isPwdBased(publicKey.keyType) {
		if _, err := dst.Write([]byte{ctPwdAsymmetric}); err != nil {
			return nil, err
		}
		if _, err := dst.Write(publicKey.spec.bytes()); err != nil {
			return nil, err
		}
	} else {
		if _, err := dst.Write([]byte{ctKeyAsymmetric}); err != nil {
			return nil, err
		}
	}
	return publicKey.publicKey.NewEncryptingWriter(dst, compression)
}

// EncryptStream encrypts src with the public key and writes to dst.
func (publicKey *PublicKey) EncryptStream(dst io.Writer, src io.Reader, compression bool) (err error) {
	encryptedWriter, err := publicKey.NewEncryptingWriter(dst, compression)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptedWriter, src); err != nil {
		return err
	}
	return encryptedWriter.Close()
}

// Encrypt encrypts data with the public key.
func (publicKey *PublicKey) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = publicKey.EncryptStream(&buf, bytes.NewReader(data), compression); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.ReadCloser, error) {
	ctTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(src, ctTypeBytes); err != nil {
		return nil, err
	}
	var ctType uint8 = ctTypeBytes[0]
	key := privateKey.key
	switch ctType {
	case ctKeyAsymmetric, ctKeySymmetric:
		if isPwdBased(privateKey.keyType) {
			return nil, errDecryptionFailedKeyRequired
		}
	case ctPwdAsymmetric, ctPwdSymmetric:
		if !isPwdBased(privateKey.keyType) {
			return nil, errDecryptionFailedPwdRequired
		}
		specBytes := make([]byte, kdfSpecLength)
		if _, err := io.ReadFull(src, specBytes); err != nil {
			return nil, err
		}
		spec, err := parseKdfSpec(specBytes)
		if err != nil {
			return nil, err
		}
		if key, err = privateKey.getKeyForPwdSpec(*spec); err != nil {
			return nil, err
		}
	default:
		return nil, errInvalidCiphertext
	}
	switch ctType {
	case ctKeyAsymmetric, ctPwdAsymmetric:
		eccPrivKey, err := asx.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		return eccPrivKey.NewDecryptingReader(src)
	case ctKeySymmetric, ctPwdSymmetric:
		symmCipher, err := newVariableKeySymmCipher(key)
		if err != nil {
			return nil, err
		}
		return symmCipher.NewDecryptingReader(src)
	}
	return nil, errInvalidCiphertext
}

// DecryptStream decrypts src and writes to dst.
func (privateKey *PrivateKey) DecryptStream(dst io.Writer, src io.Reader) (err error) {
	decryptedReader, err := privateKey.NewDecryptingReader(src)
	if err != nil {
		return err
	}
	if _, err = io.Copy(dst, decryptedReader); err != nil {
		return err
	}
	return decryptedReader.Close()
}

// Decrypt decrypts the given ciphertext and returns the decrypted data.
func (privateKey *PrivateKey) Decrypt(ciphertext []byte) (data []byte, err error) {
	var buf bytes.Buffer
	if err = privateKey.DecryptStream(&buf, bytes.NewReader(ciphertext)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
