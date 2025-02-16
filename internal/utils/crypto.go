package utils

import (
	"bytes"
	"io"
	"net/url"
	"strings"

	"xipher.org/xipher"
)

func getSanitisedValue(strOrUrl string, patternVerifier func(string) bool) string {
	if u, err := url.Parse(strOrUrl); err == nil {
		for _, values := range u.Query() {
			for _, value := range values {
				trimmedValue := strings.TrimSpace(value)
				if patternVerifier(trimmedValue) {
					return trimmedValue
				}
			}
		}
	}
	return strings.TrimSpace(strOrUrl)
}

func NewEncryptingWriter(keyOrPwd string, dst io.Writer, compress, encode bool) (encryptingWriteCloser io.WriteCloser, err error) {
	keyOrPwd = getSanitisedValue(keyOrPwd, xipher.IsPubKeyStr)
	if xipher.IsPubKeyStr(keyOrPwd) {
		var pubKey *xipher.PublicKey
		if pubKey, err = xipher.ParsePublicKeyStr(keyOrPwd); err != nil {
			return nil, err
		}
		return pubKey.NewEncryptingWriter(dst, compress, encode)
	} else {
		var secretKey *xipher.SecretKey
		if xipher.IsSecretKeyStr(keyOrPwd) {
			if secretKey, err = xipher.ParseSecretKeyStr(keyOrPwd); err != nil {
				return nil, err
			}
		} else {
			if secretKey, err = xipher.NewSecretKeyForPassword([]byte(keyOrPwd)); err != nil {
				return nil, err
			}
		}
		return secretKey.NewEncryptingWriter(dst, compress, encode)
	}
}

func EncryptStream(keyOrPwd string, dst io.Writer, src io.Reader, compress, encode bool) error {
	encryptingWriter, err := NewEncryptingWriter(keyOrPwd, dst, compress, encode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptingWriter, src); err != nil {
		return err
	}
	return encryptingWriter.Close()
}

func encryptData(keyOrPwd string, data []byte, compress bool) (string, error) {
	var buf bytes.Buffer
	if err := EncryptStream(keyOrPwd, &buf, bytes.NewReader(data), compress, true); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func EncryptData(keyOrPwd string, data []byte, compress bool) (ctStr string, ctUrl string, err error) {
	if ctStr, err = encryptData(keyOrPwd, data, compress); err == nil {
		ctUrl = xipherWebURL + "?" + xipherWebCTParamName + "=" + ctStr
		if len(ctUrl) > urlMaxLenth {
			ctUrl = ""
		}
	}
	return
}

func NewDecryptingReader(secretKeyOrPwd string, src io.Reader) (io.Reader, error) {
	secretKey, err := secretKeyFromSecret(secretKeyOrPwd)
	if err != nil {
		return nil, err
	}
	return secretKey.NewDecryptingReader(src)
}

func DecryptStream(secretKeyOrPwd string, dst io.Writer, src io.Reader) error {
	decryptingReader, err := NewDecryptingReader(secretKeyOrPwd, src)
	if err != nil {
		return err
	}
	if _, err = io.Copy(dst, decryptingReader); err != nil {
		return err
	}
	return nil
}

func DecryptData(secretKeyOrPwd string, ctStr string) ([]byte, error) {
	sanitisedCTStr := getSanitisedValue(ctStr, xipher.IsCTStr)
	if !xipher.IsCTStr(sanitisedCTStr) {
		return nil, errInvalidCipherText
	}
	var buf bytes.Buffer
	if err := DecryptStream(secretKeyOrPwd, &buf, strings.NewReader(sanitisedCTStr)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
