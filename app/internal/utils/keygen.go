package utils

import "dev.shib.me/xipher"

func PubKeyForPassword(password []byte, quantumSafe bool) (string, error) {
	privKey, err := xipher.NewPrivateKeyForPassword(password)
	if err != nil {
		return "", err
	}
	pubKey, err := privKey.PublicKey(quantumSafe)
	if err != nil {
		return "", err
	}
	return pubKeyToStr(pubKey)
}

func PubKeyForPrivKey(sk string, quantumSafe bool) (string, error) {
	privKey, err := secretKeyFromStr(sk)
	if err != nil {
		return "", err
	}
	pubKey, err := privKey.PublicKey(quantumSafe)
	if err != nil {
		return "", err
	}
	return pubKeyToStr(pubKey)
}

func KeyGen() (sk string, err error) {
	privKey, err := xipher.NewPrivateKey()
	if err != nil {
		return "", err
	}
	return secretKeyToStr(privKey)
}
