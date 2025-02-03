package utils

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"xipher.org/xipher"
)

func getSecretKey(secretKeyOrPwd string) (*xipher.SecretKey, error) {
	if IsSecretKeyStr(secretKeyOrPwd) {
		return secretKeyFromStr(secretKeyOrPwd)
	} else {
		return secretKeyFromPwd(secretKeyOrPwd)
	}
}

func DecryptingReader(secretKeyOrPwd string, src io.Reader) (io.Reader, error) {
	secretKey, err := getSecretKey(secretKeyOrPwd)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(src)
	ctPrefix, _ := reader.Peek(len(xipherTxtPrefix))
	if string(ctPrefix) != xipherTxtPrefix {
		return secretKey.NewDecryptingReader(reader)
	}
	reader.Discard(len(xipherTxtPrefix))
	return secretKey.NewDecryptingReader(decodingReader(reader))
}

func DecryptStream(secretKeyOrPwd string, dst io.Writer, src io.Reader) error {
	decryptingReader, err := DecryptingReader(secretKeyOrPwd, src)
	if err != nil {
		return err
	}
	if _, err = io.Copy(dst, decryptingReader); err != nil {
		return err
	}
	return nil
}

func isCTStr(str string) bool {
	return len(str) >= len(xipherTxtPrefix) && str[:len(xipherTxtPrefix)] == xipherTxtPrefix
}

func DecryptData(secretKeyOrPwd string, ctStr string) ([]byte, error) {
	sanitisedCTStr := getSanitisedValue(ctStr, isCTStr)
	if !isCTStr(sanitisedCTStr) {
		return nil, errInvalidCipherText
	}
	var buf bytes.Buffer
	if err := DecryptStream(secretKeyOrPwd, &buf, strings.NewReader(sanitisedCTStr)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
