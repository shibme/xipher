package xipher

import (
	"gopkg.shib.me/xipher/chacha20poly1305"
	"gopkg.shib.me/xipher/ecc"
)

func (privateKey *PrivateKey) getKeyForPwdSpecBytes(pwdSpecBytes []byte) (key []byte, err error) {
	key = privateKey.pwdSpecKeyMap[string(pwdSpecBytes)]
	if key == nil || len(key) == 0 {
		key, err = keyFromArgonSpecBytes(*privateKey.password, pwdSpecBytes)
		privateKey.pwdSpecKeyMap[string(pwdSpecBytes)] = key
	}
	return key, nil
}

func (privateKey *PrivateKey) pwdSymmetricDecrypt(ciphertext []byte, compression bool) (data []byte, err error) {
	if privateKey.password == nil {
		return nil, errDecryptionFailedPwdNotFound
	}
	if len(ciphertext) < ctMinLenPwdSymmetric {
		return nil, errIncorrectCiphertext
	}
	pwdSpec := ciphertext[:kdfSpecLength]
	key, err := privateKey.getKeyForPwdSpecBytes(pwdSpec)
	if err != nil {
		return nil, err
	}
	decrypter, err := chacha20poly1305.Get(key)
	if err != nil {
		return nil, err
	}
	return decrypter.Decrypt(ciphertext[kdfSpecLength:], compression)
}

func (privateKey *PrivateKey) keySymmetricDecrypt(ciphertext []byte, compression bool) (data []byte, err error) {
	if len(ciphertext) < ctMinLenKeySymmetric {
		return nil, errIncorrectCiphertext
	}
	decrypter, err := chacha20poly1305.Get(*privateKey.key)
	if err != nil {
		return nil, err
	}
	return decrypter.Decrypt(ciphertext[kdfSpecLength:], compression)
}

func (privateKey *PrivateKey) pwdAsymmetricDecrypt(ciphertext []byte, compression bool) (data []byte, err error) {
	if privateKey.password == nil {
		return nil, errDecryptionFailedPwdNotFound
	}
	if len(ciphertext) < ctMinLenPwdAsymmetric {
		return nil, errIncorrectCiphertext
	}
	pwdSpec := ciphertext[:kdfSpecLength]
	key, err := privateKey.getKeyForPwdSpecBytes(pwdSpec)
	if err != nil {
		return nil, err
	}
	eccPrivKey, err := ecc.GetPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return eccPrivKey.Decrypt(ciphertext[kdfSpecLength:], compression)
}

func (privateKey *PrivateKey) keyAsymmetricDecrypt(ciphertext []byte, compression bool) (data []byte, err error) {
	if len(ciphertext) < ctMinLenKeyAsymmetric {
		return nil, errIncorrectCiphertext
	}
	eccPrivKey, err := ecc.GetPrivateKey(*privateKey.key)
	if err != nil {
		return nil, err
	}
	return eccPrivKey.Decrypt(ciphertext[kdfSpecLength:], compression)
}

func (privateKey *PrivateKey) Decrypt(ciphertext []byte, compression bool) (data []byte, err error) {
	if len(ciphertext) < ciphertextMinLength {
		return nil, errIncorrectCiphertext
	}
	xipherType := ciphertext[0]
	ciphertext = ciphertext[1:]
	switch xipherType {
	case pwdSymmetric:
		return privateKey.pwdSymmetricDecrypt(ciphertext, compression)
	case keySymmetric:
		return privateKey.keySymmetricDecrypt(ciphertext, compression)
	case pwdAsymmetric:
		return privateKey.pwdAsymmetricDecrypt(ciphertext, compression)
	case keyAsymmetric:
		return privateKey.keyAsymmetricDecrypt(ciphertext, compression)
	default:
		return nil, errIncorrectCiphertext
	}
}
