package utils

import "dev.shib.me/xipher"

func pubKeyToStr(pubKey *xipher.PublicKey) (string, error) {
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return "", err
	}
	return xipherPublicKeyPrefix + encode(pubKeyBytes), nil
}

func secretKeyToStr(secretKey *xipher.PrivateKey) (string, error) {
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

func secretKeyFromStr(secretKeyStr string) (*xipher.PrivateKey, error) {
	if len(secretKeyStr) < len(xipherSecretKeyPrefix) || secretKeyStr[:len(xipherSecretKeyPrefix)] != xipherSecretKeyPrefix {
		return nil, errInvalidXipherPrivKey
	}
	keyBytes, err := decode(secretKeyStr[len(xipherSecretKeyPrefix):])
	if err != nil {
		return nil, err
	}
	return xipher.ParsePrivateKey(keyBytes)
}
