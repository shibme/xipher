package utils

import "dev.shib.me/xipher"

func ctToStr(ct []byte) string {
	return xipherTxtPrefix + encode(ct)
}

func EncryptDataWithPubKey(pubKey *xipher.PublicKey, data []byte) (string, error) {
	ct, err := pubKey.Encrypt(data, true)
	if err != nil {
		return "", err
	}
	return ctToStr(ct), nil
}

func EncryptDataWithPubKeyStr(pubKeyStr string, data []byte) (string, error) {
	pubKey, err := PubKeyFromStr(pubKeyStr)
	if err != nil {
		return "", err
	}
	return EncryptDataWithPubKey(pubKey, data)
}
