package utils

import (
	"io"

	"dev.shib.me/xipher"
)

func ctToStr(ct []byte) string {
	return xipherTxtPrefix + encode(ct)
}

func EncryptData(keyOrPwd string, data []byte) (string, error) {
	if IsPubKeyStr(keyOrPwd) {
		pubKey, err := pubKeyFromStr(keyOrPwd)
		if err != nil {
			return "", err
		}
		ct, err := pubKey.Encrypt(data, true)
		if err != nil {
			return "", err
		}
		return ctToStr(ct), nil
	} else if IsSecretKeyStr(keyOrPwd) {
		secretKey, err := secretKeyFromStr(keyOrPwd)
		if err != nil {
			return "", err
		}
		ct, err := secretKey.Encrypt(data, true)
		if err != nil {
			return "", err
		}
		return ctToStr(ct), nil
	} else {
		secretKey, err := xipher.NewSecretKeyForPassword([]byte(keyOrPwd))
		if err != nil {
			return "", err
		}
		ct, err := secretKey.Encrypt(data, true)
		if err != nil {
			return "", err
		}
		return ctToStr(ct), nil
	}
}

func EncryptingWriter(keyOrPwd string, dst io.Writer, compress bool) (io.WriteCloser, error) {
	if IsPubKeyStr(keyOrPwd) {
		pubKey, err := pubKeyFromStr(keyOrPwd)
		if err != nil {
			return nil, err
		}
		return pubKey.NewEncryptingWriter(dst, compress)
	} else if IsSecretKeyStr(keyOrPwd) {
		secretKey, err := secretKeyFromStr(keyOrPwd)
		if err != nil {
			return nil, err
		}
		return secretKey.NewEncryptingWriter(dst, compress)
	} else {
		secretKey, err := xipher.NewSecretKeyForPassword([]byte(keyOrPwd))
		if err != nil {
			return nil, err
		}
		return secretKey.NewEncryptingWriter(dst, compress)
	}
}

func EncryptStream(keyOrPwd string, dst io.Writer, src io.Reader, compress bool) (err error) {
	encryptingWriter, err := EncryptingWriter(keyOrPwd, dst, compress)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptingWriter, src); err != nil {
		return err
	}
	return encryptingWriter.Close()
}
