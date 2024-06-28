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

func EncryptStream(keyOrPwd string, dst io.Writer, src io.Reader, compress bool) (err error) {
	if IsPubKeyStr(keyOrPwd) {
		pubKey, err := pubKeyFromStr(keyOrPwd)
		if err != nil {
			return err
		}
		return pubKey.EncryptStream(dst, src, compress)
	} else if IsSecretKeyStr(keyOrPwd) {
		secretKey, err := secretKeyFromStr(keyOrPwd)
		if err != nil {
			return err
		}
		return secretKey.EncryptStream(dst, src, compress)
	} else {
		secretKey, err := xipher.NewSecretKeyForPassword([]byte(keyOrPwd))
		if err != nil {
			return err
		}
		return secretKey.EncryptStream(dst, src, compress)
	}
}
