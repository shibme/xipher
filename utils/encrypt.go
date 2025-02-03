package utils

import (
	"bytes"
	"io"

	"xipher.org/xipher"
)

type doubleWriteCloser struct {
	primary   io.WriteCloser
	secondary io.WriteCloser
}

func (dwc *doubleWriteCloser) Write(p []byte) (n int, err error) {
	return dwc.primary.Write(p)
}

func (dwc *doubleWriteCloser) Close() error {
	if err := dwc.primary.Close(); err != nil {
		return err
	}
	return dwc.secondary.Close()
}

func EncryptingWriter(keyOrPwd string, dst io.Writer, compress, encode bool) (encryptingWriteCloser io.WriteCloser, err error) {
	keyOrPwd = getSanitisedValue(keyOrPwd, isPubKeyStr)
	var encodeWriteCloser io.WriteCloser
	if encode {
		dst.Write([]byte(xipherTxtPrefix))
		encodeWriteCloser = encodingWriter(dst)
		dst = encodeWriteCloser
	}
	if isPubKeyStr(keyOrPwd) {
		var pubKey *xipher.PublicKey
		if pubKey, err = pubKeyFromStr(keyOrPwd); err != nil {
			return nil, err
		}
		encryptingWriteCloser, err = pubKey.NewEncryptingWriter(dst, compress)
	} else {
		var secretKey *xipher.SecretKey
		if IsSecretKeyStr(keyOrPwd) {
			if secretKey, err = secretKeyFromStr(keyOrPwd); err != nil {
				return nil, err
			}
		} else {
			if secretKey, err = xipher.NewSecretKeyForPassword([]byte(keyOrPwd)); err != nil {
				return nil, err
			}
		}
		encryptingWriteCloser, err = secretKey.NewEncryptingWriter(dst, compress)
	}
	if err != nil {
		return nil, err
	}
	if encodeWriteCloser != nil {
		return &doubleWriteCloser{encryptingWriteCloser, encodeWriteCloser}, nil
	}
	return encryptingWriteCloser, nil
}

func EncryptStream(keyOrPwd string, dst io.Writer, src io.Reader, compress, encode bool) error {
	encryptingWriter, err := EncryptingWriter(keyOrPwd, dst, compress, encode)
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
