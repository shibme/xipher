package utils

import (
	"dev.shib.me/xipher"
)

func NewSecretKey() (sk string, err error) {
	privKey, err := xipher.NewPrivateKey()
	if err != nil {
		return "", err
	}
	return secretKeyToStr(privKey)
}

func GetPublicKey(secret string, quantumSafe bool) (string, error) {
	secretKey, err := secretKeyFromStr(secret)
	if err != nil {
		secretKey, err = xipher.NewPrivateKeyForPassword([]byte(secret))
		if err != nil {
			return "", err
		}
	}
	pubKey, err := secretKey.PublicKey(quantumSafe)
	if err != nil {
		return "", err
	}
	return pubKeyToStr(pubKey)
}
