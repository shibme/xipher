package utils

import "dev.shib.me/xipher"

func ctFromStr(ctStr string) ([]byte, error) {
	if len(ctStr) < len(xipherTxtPrefix) || ctStr[:len(xipherTxtPrefix)] != xipherTxtPrefix {
		return nil, errInvalidCipherText
	}
	return decode(ctStr[len(xipherTxtPrefix):])
}

func DecryptTextWithSecretKey(secretKey *xipher.PrivateKey, ctStr string) (string, error) {
	ct, err := ctFromStr(ctStr)
	if err != nil {
		return "", err
	}
	text, err := secretKey.Decrypt(ct)
	if err != nil {
		return "", err
	}
	return string(text), nil
}

func DecryptTextWithSecretKeyStr(sk, ctStr string) (string, error) {
	secretKey, err := secretKeyFromStr(sk)
	if err != nil {
		return "", err
	}
	return DecryptTextWithSecretKey(secretKey, ctStr)
}

func DecryptTextWithPassword(password []byte, ctStr string) (string, error) {
	secretKey, err := xipher.NewPrivateKeyForPassword(password)
	if err != nil {
		return "", err
	}
	return DecryptTextWithSecretKey(secretKey, ctStr)
}
