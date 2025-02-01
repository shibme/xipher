package utils

import (
	"io"

	"xipher.org/xipher"
)

func getSecretKey(secretKeyOrPwd string) (*xipher.SecretKey, error) {
	if IsSecretKeyStr(secretKeyOrPwd) {
		return secretKeyFromStr(secretKeyOrPwd)
	} else {
		return secretKeyFromPwd(secretKeyOrPwd)
	}
}

func isCTStr(str string) bool {
	return len(str) >= len(xipherTxtPrefix) && str[:len(xipherTxtPrefix)] == xipherTxtPrefix
}

func getCTFromStr(ctStr string) ([]byte, error) {
	sanitisedCTStr := getSanitisedValue(ctStr, isCTStr)
	if isCTStr(sanitisedCTStr) {
		return decode(sanitisedCTStr[len(xipherTxtPrefix):])
	}
	return nil, errInvalidCipherText
}

func DecryptData(secretKeyOrPwd string, ctStr string) ([]byte, error) {
	ct, err := getCTFromStr(ctStr)
	if err != nil {
		return nil, err
	}
	secretKey, err := getSecretKey(secretKeyOrPwd)
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
