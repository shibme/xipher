package utils

import "errors"

const (
	appNameLowerCase      = "xipher"
	xipherPublicKeyPrefix = "XPK_"
	xipherSecretKeyPrefix = "XSK_"
	xipherTxtPrefix       = "XCT_"
	xipherPubKeyFileExt   = ".xpk"
	xipherFileExt         = "." + appNameLowerCase
)

var (
	errInvalidXipherPubKey  = errors.New("invalid xipher public key")
	errInvalidXipherPrivKey = errors.New("invalid xipher private key")
	errInvalidCipherText    = errors.New("invalid cipher text")
)
