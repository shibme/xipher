package utils

import "errors"

const (
	appNameLowerCase      = "xipher"
	xipherPublicKeyPrefix = "XPK_"
	xipherSecretKeyPrefix = "XSK_"
	xipherTxtPrefix       = "XCT_"
	xipherPubKeyFileExt   = ".xpk"
	xipherFileExt         = "." + appNameLowerCase
	secretKeyStrRegex     = "^" + xipherSecretKeyPrefix + "[A-Z2-7]{106}$"
)

var (
	errInvalidXipherPubKey  = errors.New("invalid xipher public key")
	errInvalidXipherPrivKey = errors.New("invalid xipher private key")
	errInvalidCipherText    = errors.New("invalid cipher text")
)
