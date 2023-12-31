package xipher

import (
	"bytes"
	"io"

	"golang.org/x/crypto/argon2"
	"gopkg.shib.me/xipher/internal/ecc"
	"gopkg.shib.me/xipher/internal/symmcipher"
)

// EncryptStream encrypts src with the private key treating it as a symmetric key and writes to dst.
func (privateKey *PrivateKey) EncryptStream(dst io.Writer, src io.Reader, compression bool) (err error) {
	if privateKey.isPwdBased() {
		dst.Write([]byte{ctPwdSymmetric})
		dst.Write(privateKey.spec.bytes())
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
		dst.Write(publicKey.spec.bytes())
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

func (privateKey *PrivateKey) getKeyForPwdSpec(spec kdfSpec) (key []byte, err error) {
	specBytes := spec.bytes()
	key = privateKey.specKeyMap[string(specBytes)]
	if len(key) == 0 {
		key = spec.getCipherKey(*privateKey.password)
		privateKey.specKeyMap[string(specBytes)] = key
	}
	return key, nil
}

func symmetricDecrypt(dst io.Writer, src io.Reader, key []byte) (err error) {
	decrypter, err := symmcipher.New(key)
	if err != nil {
		return err
	}
	return decrypter.Decrypt(dst, src)
}

func asymmetricDecrypt(dst io.Writer, src io.Reader, key []byte) (err error) {
	eccPrivKey, err := ecc.GetPrivateKey(key)
	if err != nil {
		return err
	}
	return eccPrivKey.Decrypt(dst, src)
}

// DecryptStream decrypts src and writes to dst.
func (privateKey *PrivateKey) DecryptStream(dst io.Writer, src io.Reader) (err error) {
	ctTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(src, ctTypeBytes); err != nil {
		return err
	}
	ctType := ctTypeBytes[0]
	key := privateKey.key
	if ctType == ctPwdSymmetric || ctType == ctPwdAsymmetric {
		specBytes := make([]byte, kdfSpecLength)
		if _, err := io.ReadFull(src, specBytes); err != nil {
			return err
		}
		spec, err := parseKdfSpec(specBytes)
		if err != nil {
			return err
		}
		if key, err = privateKey.getKeyForPwdSpec(*spec); err != nil {
			return err
		}
	}
	switch ctType {
	case ctKeySymmetric, ctPwdSymmetric:
		return symmetricDecrypt(dst, src, key)
	case ctKeyAsymmetric, ctPwdAsymmetric:
		return asymmetricDecrypt(dst, src, key)
	default:
		return errInvalidCiphertext
	}
}

// Decrypt decrypts the given ciphertext and returns the decrypted data.
func (privateKey *PrivateKey) Decrypt(ciphertext []byte) (data []byte, err error) {
	var buf bytes.Buffer
	if err = privateKey.DecryptStream(&buf, bytes.NewReader(ciphertext)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Hash returns the argon2 hash of the given data.
func Hash(data []byte, length uint32) []byte {
	return argon2.IDKey(data, nil, uint32(argon2Iterations), uint32(argon2Memory)*1024, argon2Threads, length)
}
