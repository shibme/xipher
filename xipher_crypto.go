package xipher

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"dev.shib.me/xipher/crypto/asx"
	"dev.shib.me/xipher/crypto/xcp"
)

func newVariableKeySymmCipher(key []byte) (*xcp.SymmetricCipher, error) {
	if len(key) == secretKeyBaseLength {
		keySum := sha256.Sum256(key)
		key = keySum[:]
	}
	return xcp.New(key)
}

func (secretKey *SecretKey) NewEncryptingWriter(dst io.Writer, compress bool) (writer io.WriteCloser, err error) {
	if isPwdBased(secretKey.keyType) {
		if _, err := dst.Write([]byte{ctPwdSymmetric}); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write ciphertext type", "xipher")
		}
		if _, err := dst.Write(secretKey.spec.bytes()); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write kdf spec", "xipher")
		}
	} else {
		if _, err := dst.Write([]byte{ctKeySymmetric}); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write ciphertext type", "xipher")
		}
	}
	if secretKey.symmCipher == nil {
		if secretKey.symmCipher, err = newVariableKeySymmCipher(secretKey.key); err != nil {
			return nil, err
		}
	}
	return secretKey.symmCipher.NewEncryptingWriter(dst, compress)
}

// EncryptStream encrypts src with the secret key treating it as a symmetric key and writes to dst.
func (secretKey *SecretKey) EncryptStream(dst io.Writer, src io.Reader, compress bool) (err error) {
	encryptedWriter, err := secretKey.NewEncryptingWriter(dst, compress)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptedWriter, src); err != nil {
		return err
	}
	return encryptedWriter.Close()
}

// Encrypt encrypts data with the secret key treating it as a symmetric key.
func (secretKey *SecretKey) Encrypt(data []byte, compress bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = secretKey.EncryptStream(&buf, bytes.NewReader(data), compress); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compress bool) (writer io.WriteCloser, err error) {
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
	return publicKey.publicKey.NewEncryptingWriter(dst, compress)
}

// EncryptStream encrypts src with the public key and writes to dst.
func (publicKey *PublicKey) EncryptStream(dst io.Writer, src io.Reader, compress bool) (err error) {
	encryptedWriter, err := publicKey.NewEncryptingWriter(dst, compress)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptedWriter, src); err != nil {
		return err
	}
	return encryptedWriter.Close()
}

// Encrypt encrypts data with the public key.
func (publicKey *PublicKey) Encrypt(data []byte, compress bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = publicKey.EncryptStream(&buf, bytes.NewReader(data), compress); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (secretKey *SecretKey) NewDecryptingReader(src io.Reader) (io.Reader, error) {
	ctTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(src, ctTypeBytes); err != nil {
		return nil, fmt.Errorf("%s: decrypter failed to read ciphertext type", "xipher")
	}
	var ctType uint8 = ctTypeBytes[0]
	key := secretKey.key
	switch ctType {
	case ctKeyAsymmetric, ctKeySymmetric:
		if isPwdBased(secretKey.keyType) {
			return nil, errDecryptionFailedKeyRequired
		}
	case ctPwdAsymmetric, ctPwdSymmetric:
		if !isPwdBased(secretKey.keyType) {
			return nil, errDecryptionFailedPwdRequired
		}
		specBytes := make([]byte, kdfSpecLength)
		if _, err := io.ReadFull(src, specBytes); err != nil {
			return nil, fmt.Errorf("%s: decrypter failed to read kdf spec", "xipher")
		}
		spec, err := parseKdfSpec(specBytes)
		if err != nil {
			return nil, err
		}
		key = secretKey.getKeyForPwdSpec(*spec)
	default:
		return nil, errInvalidCiphertext
	}
	switch ctType {
	case ctKeyAsymmetric, ctPwdAsymmetric:
		asxPrivKey, err := asx.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		return asxPrivKey.NewDecryptingReader(src)
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
func (secretKey *SecretKey) DecryptStream(dst io.Writer, src io.Reader) (err error) {
	decryptedReader, err := secretKey.NewDecryptingReader(src)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, decryptedReader)
	return err
}

// Decrypt decrypts the given ciphertext and returns the decrypted data.
func (secretKey *SecretKey) Decrypt(ciphertext []byte) (data []byte, err error) {
	var buf bytes.Buffer
	if err = secretKey.DecryptStream(&buf, bytes.NewReader(ciphertext)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
