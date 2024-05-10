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

func DecryptText(secret string, ctStr string) (string, error) {
	secretKey, err := secretKeyFromStr(secret)
	if err != nil {
		secretKey, err = xipher.NewPrivateKeyForPassword([]byte(secret))
		if err != nil {
			return "", err
		}
	}
	return DecryptTextWithSecretKey(secretKey, ctStr)
}
