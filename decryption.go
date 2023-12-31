package xipher

import (
	"bytes"
	"io"

	"gopkg.shib.me/xipher/internal/ecc"
	"gopkg.shib.me/xipher/internal/symmcipher"
)

func (privateKey *PrivateKey) getKeyForPwdSpec(spec kdfSpec) (key []byte, err error) {
	specBytes := spec.Bytes()
	key = privateKey.specKeyMap[string(specBytes)]
	if key == nil || len(key) == 0 {
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
		specBytes := make([]byte, specLength)
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
