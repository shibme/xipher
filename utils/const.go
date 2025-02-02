package utils

import (
	"errors"

	"xipher.org/xipher"
)

const (
	appNameLowerCase      = "xipher"
	xipherPublicKeyPrefix = "XPK_"
	xipherSecretKeyPrefix = "XSK_"
	xipherTxtPrefix       = "XCT_"
	xipherPubKeyFileExt   = ".xpk"
	xipherFileExt         = "." + appNameLowerCase
	secretKeyStrRegex     = "^" + xipherSecretKeyPrefix + "[A-Z2-7]{106}$"
	xipherWebKeyParamName = "xk"
	xipherWebCTParamName  = "xt"
	urlMaxLenth           = 65536
)

var (
	xipherWebURL    = xipher.Info.Web
	pwdSecretKeyMap = make(map[string]*xipher.SecretKey)

	errInvalidXipherPubKey    = errors.New("invalid xipher public key")
	errInvalidXipherSecretKey = errors.New("invalid xipher secret key")
	errInvalidCipherText      = errors.New("invalid cipher text")
)
