package xipher

import (
	"bytes"
	"io"

	"dev.shib.me/xipher/internal/ecc"
	"dev.shib.me/xipher/internal/symcipher"
)

func (privateKey *PrivateKey) NewEncryptingWriter(dst io.Writer, compression bool) (writer io.WriteCloser, err error) {
	if privateKey.isPwdBased() {
		dst.Write([]byte{ctPwdSymmetric})
		dst.Write(privateKey.spec.bytes())
	} else {
		dst.Write([]byte{ctKeySymmetric})
	}
	if privateKey.symEncrypter == nil {
		if privateKey.symEncrypter, err = symcipher.New(privateKey.key); err != nil {
			return nil, err
		}
	}
	return privateKey.symEncrypter.NewEncryptingWriter(dst, compression)
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
	if publicKey.isPwdBased() {
		dst.Write([]byte{ctPwdAsymmetric})
		dst.Write(publicKey.spec.bytes())
	} else {
		dst.Write([]byte{ctKeyAsymmetric})
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

func (privateKey *PrivateKey) getKeyForPwdSpec(spec kdfSpec) (key []byte, err error) {
	specBytes := spec.bytes()
	key = privateKey.specKeyMap[string(specBytes)]
	if len(key) == 0 {
		key = spec.getCipherKey(*privateKey.password)
		privateKey.specKeyMap[string(specBytes)] = key
	}
	return key, nil
}

func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.ReadCloser, error) {
	ctTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(src, ctTypeBytes); err != nil {
		return nil, err
	}
	ctType := ctTypeBytes[0]
	key := privateKey.key
	if ctType == ctPwdSymmetric || ctType == ctPwdAsymmetric {
		if !privateKey.isPwdBased() {
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
	} else if (ctType == ctKeySymmetric || ctType == ctKeyAsymmetric) && privateKey.isPwdBased() {
		return nil, errDecryptionFailedKeyRequired
	}
	switch ctType {
	case ctKeySymmetric, ctPwdSymmetric:
		decrypter, err := symcipher.New(key)
		if err != nil {
			return nil, err
		}
		return decrypter.NewDecryptingReader(src)
	case ctKeyAsymmetric, ctPwdAsymmetric:
		eccPrivKey, err := ecc.GetPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return eccPrivKey.NewDecryptingReader(src)
	default:
		return nil, errInvalidCiphertext
	}
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
