package utils

import (
	"regexp"

	"xipher.org/xipher"
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

func pubKeyFromStr(pubKeyStr string) (*xipher.PublicKey, error) {
	if !IsPubKeyStr(pubKeyStr) {
		return nil, errInvalidXipherPubKey
	}
	keyBytes, err := decode(pubKeyStr[len(xipherPublicKeyPrefix):])
	if err != nil {
		return nil, err
	}
	return xipher.ParsePublicKey(keyBytes)
}

func secretKeyFromStr(secretKeyStr string) (*xipher.SecretKey, error) {
	if !IsSecretKeyStr(secretKeyStr) {
		return nil, errInvalidXipherSecretKey
	}
	keyBytes, err := decode(secretKeyStr[len(xipherSecretKeyPrefix):])
	if err != nil {
		return nil, err
	}
	return xipher.ParseSecretKey(keyBytes)
}

func secretKeyFromPwd(pwd string) (xsk *xipher.SecretKey, err error) {
	xsk = pwdSecretKeyMap[pwd]
	if xsk == nil {
		if xsk, err = xipher.NewSecretKeyForPassword([]byte(pwd)); err != nil {
			return nil, err
		}
		pwdSecretKeyMap[pwd] = xsk
	}
	return
}

func secretKeyFromSecret(secretKeyOrPwd string) (*xipher.SecretKey, error) {
	secretKey, err := secretKeyFromStr(secretKeyOrPwd)
	if err != nil {
		secretKey, err = xipher.NewSecretKeyForPassword([]byte(secretKeyOrPwd))
		if err != nil {
			return nil, err
		}
	}
	return secretKey, nil
}

func NewSecretKey() (sk string, err error) {
	secretKey, err := xipher.NewSecretKey()
	if err != nil {
		return "", err
	}
	return secretKeyToStr(secretKey)
}

func GetPublicKey(secretKeyOrPwd string, quantumSafe bool) (string, error) {
	secretKey, err := secretKeyFromSecret(secretKeyOrPwd)
	if err != nil {
		return "", err
	}
	pubKey, err := secretKey.PublicKey(quantumSafe)
	if err != nil {
		return "", err
	}
	return pubKeyToStr(pubKey)
}

func IsPubKeyStr(pubKeyStr string) bool {
	return len(pubKeyStr) > len(xipherPublicKeyPrefix) && pubKeyStr[:len(xipherPublicKeyPrefix)] == xipherPublicKeyPrefix
}

func IsSecretKeyStr(secretKeyStr string) bool {
	return regexp.MustCompile(secretKeyStrRegex).MatchString(secretKeyStr)
}
