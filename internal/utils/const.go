package utils

import (
	"errors"
	"strings"

	"xipher.org/xipher"
)

const (
	urlMaxLength = 65536
)

var (
	// xipherWebURL is the web app base URL with a guaranteed trailing slash, so
	// fragment URLs (base + "#" + payload) match those the web app emits from its
	// served root, e.g. "https://xipher.org/#XPK_...".
	xipherWebURL         = strings.TrimRight(xipher.Info.Web, "/") + "/"
	pwdSecretKeyMap      = make(map[string]*xipher.SecretKey)
	errInvalidCipherText = errors.New("invalid ciphertext")
)
