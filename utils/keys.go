package utils

import (
	"regexp"

	"dev.shib.me/xipher"
)

func pubKeyToStr(pubKey *xipher.PublicKey) (string, error) {
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return "", err
	}
	return xipherPublicKeyPrefix + encode(pubKeyBytes), nil
}

func secretKeyToStr(secretKey *xipher.SecretKey) (string, error) {
	secretKeyBytes, err := secretKey.Bytes()
	if err != nil {
		return "", err
	}
	return xipherSecretKeyPrefix + encode(secretKeyBytes), nil
}

func PubKeyFromStr(pubKeyStr string) (*xipher.PublicKey, error) {
	if len(pubKeyStr) < len(xipherPublicKeyPrefix) || pubKeyStr[:len(xipherPublicKeyPrefix)] != xipherPublicKeyPrefix {
		return nil, errInvalidXipherPubKey
	}
	keyBytes, err := decode(pubKeyStr[len(xipherPublicKeyPrefix):])
	if err != nil {
		return nil, err
	}
	return xipher.ParsePublicKey(keyBytes)
}

func secretKeyFromStr(secretKeyStr string) (*xipher.SecretKey, error) {
	if !regexp.MustCompile(secretKeyStrRegex).MatchString(secretKeyStr) {
		return nil, errInvalidXipherPrivKey
	}
	keyBytes, err := decode(secretKeyStr[len(xipherSecretKeyPrefix):])
	if err != nil {
		return nil, err
	}
	return xipher.ParseSecretKey(keyBytes)
}

func SecretKeyFromSecret(secret string) (*xipher.SecretKey, error) {
	secretKey, err := secretKeyFromStr(secret)
	if err != nil {
		secretKey, err = xipher.NewSecretKeyForPassword([]byte(secret))
		if err != nil {
			return nil, err
		}
	}
	return secretKey, nil
}
