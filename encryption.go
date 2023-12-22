package xipher

import (
	"gopkg.shib.me/xipher/chacha20poly1305"
)

func (privateKey *PrivateKey) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	if privateKey.symmetricEncrypter == nil {
		privateKey.symmetricEncrypter, err = chacha20poly1305.Get(*privateKey.key)
		if err != nil {
			return nil, err
		}
	}
	if ciphertext, err = privateKey.symmetricEncrypter.Encrypt(data, compression); err != nil {
		return nil, err
	}
	if privateKey.kdfSpec != nil {
		return append([]byte{pwdSymmetric}, append(*privateKey.kdfSpec, ciphertext...)...), nil
	} else {
		return append([]byte{keySymmetric}, ciphertext...), nil
	}
}

func (publicKey *PublicKey) Encrypt(data []byte, compression bool) (ciphertext []byte, err error) {
	ciphertext, err = publicKey.publicKey.Encrypt(data, compression)
	if err != nil {
		return nil, err
	}
	if publicKey.kdfSpec != nil {
		return append([]byte{pwdAsymmetric}, append(*publicKey.kdfSpec, ciphertext...)...), nil
	} else {
		return append([]byte{keyAsymmetric}, ciphertext...), nil
	}
}
