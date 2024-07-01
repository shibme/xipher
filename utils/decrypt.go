package utils

import (
	"io"

	"dev.shib.me/xipher"
)

func getSecretKey(secretKeyOrPwd string) (*xipher.SecretKey, error) {
	if IsSecretKeyStr(secretKeyOrPwd) {
		return secretKeyFromStr(secretKeyOrPwd)
	} else {
		return secretKeyFromPwd(secretKeyOrPwd)
	}
}

func DecryptData(secretKeyOrPwd string, ctStr string) ([]byte, error) {
	secretKey, err := getSecretKey(secretKeyOrPwd)
	if err != nil {
		return nil, err
	}
	if len(ctStr) < len(xipherTxtPrefix) || ctStr[:len(xipherTxtPrefix)] != xipherTxtPrefix {
		return nil, errInvalidCipherText
	}
	ct, err := decode(ctStr[len(xipherTxtPrefix):])
	if err != nil {
		return nil, err
	}
	data, err := secretKey.Decrypt(ct)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func DecryptingReader(secretKeyOrPwd string, src io.Reader) (io.Reader, error) {
	secretKey, err := getSecretKey(secretKeyOrPwd)
	if err != nil {
		return nil, err
	}
	return secretKey.NewDecryptingReader(src)
}

func DecryptStream(secretKeyOrPwd string, dst io.Writer, src io.Reader) (err error) {
	secretKey, err := getSecretKey(secretKeyOrPwd)
	if err != nil {
		return err
	}
	return secretKey.DecryptStream(dst, src)
}
