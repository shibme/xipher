package utils

import "xipher.org/xipher"

func getCachedSecretKeyForPwd(pwd string) (xsk *xipher.SecretKey, err error) {
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
	if xipher.IsSecretKeyStr(secretKeyOrPwd) {
		return xipher.ParseSecretKeyStr(secretKeyOrPwd)
	} else {
		return getCachedSecretKeyForPwd(secretKeyOrPwd)
	}
}

func GetPublicKey(secretKeyOrPwd string, quantumSafe bool) (pubKeyStr, pubKeyUrl string, err error) {
	secretKey, err := secretKeyFromSecret(secretKeyOrPwd)
	if err != nil {
		return "", "", err
	}
	pubKey, err := secretKey.PublicKey(quantumSafe)
	if err != nil {
		return "", "", err
	}
	if pubKeyStr, err = pubKey.String(); err != nil {
		return "", "", err
	}
	pubKeyUrl = xipherWebURL + "#" + pubKeyStr
	if len(pubKeyUrl) > urlMaxLenth {
		pubKeyUrl = ""
	}
	return
}

func GetSanitisedKeyOrPwd(keyPwdStr string) (sanitisedKey string, isKey bool) {
	keyPwdStr = getSanitisedValue(keyPwdStr, xipher.IsPubKeyStr)
	return keyPwdStr, xipher.IsPubKeyStr(keyPwdStr) || xipher.IsSecretKeyStr(keyPwdStr)
}
