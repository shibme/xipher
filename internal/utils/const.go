package utils

import (
	"errors"

	"xipher.org/xipher"
)

const (
	urlMaxLenth = 65536
)

var (
	xipherWebURL         = xipher.Info.Web
	pwdSecretKeyMap      = make(map[string]*xipher.SecretKey)
	errInvalidCipherText = errors.New("invalid ciphertext")
)
