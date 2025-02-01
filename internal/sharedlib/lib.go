package main

import (
	"C"
)
import (
	"unsafe"

	"xipher.org/xipher/utils"
)

func xipherNewSecretKey(secretKey **C.char, secretKeyLength *C.int, errMessage **C.char, errLength *C.int) {
	if sk, err := utils.NewSecretKey(); err != nil {
		*secretKey = nil
		*secretKeyLength = 0
		*errMessage = C.CString(err.Error())
		*errLength = C.int(len(err.Error()))
	} else {
		*secretKey = C.CString(sk)
		*secretKeyLength = C.int(len(sk))
		*errMessage = nil
		*errLength = 0
	}
}

func xipherGetPublicKey(secretKeyOrPassword *C.char, quantumSafe C.int, publicKey **C.char, publicKeyLength *C.int, errMessage **C.char, errLength *C.int) {
	if pubKey, _, err := utils.GetPublicKey(C.GoString(secretKeyOrPassword), quantumSafe != 0); err != nil {
		*publicKey = nil
		*publicKeyLength = 0
		*errMessage = C.CString(err.Error())
		*errLength = C.int(len(err.Error()))
	} else {
		*publicKey = C.CString(pubKey)
		*publicKeyLength = C.int(len(pubKey))
		*errMessage = nil
		*errLength = 0
	}
}

func xipherEncryptData(keyOrPassword *C.char, data *C.char, cipherText **C.char, cipherTextLength *C.int, errMessage **C.char, errLength *C.int) {
	dataBytes := C.GoBytes(unsafe.Pointer(data), C.int(len(C.GoString(data))))
	if ct, _, err := utils.EncryptData(C.GoString(keyOrPassword), dataBytes, true); err != nil {
		*cipherText = nil
		*cipherTextLength = 0
		*errMessage = C.CString(err.Error())
		*errLength = C.int(len(err.Error()))
	} else {
		*cipherText = C.CString(ct)
		*cipherTextLength = C.int(len(ct))
		*errMessage = nil
		*errLength = 0
	}
}

func xipherDecryptData(secretKeyOrPassword *C.char, cipherText *C.char, data **C.char, dataLength *C.int, errMessage **C.char, errLength *C.int) {
	if dataBytes, err := utils.DecryptData(C.GoString(secretKeyOrPassword), C.GoString(cipherText)); err != nil {
		*data = nil
		*dataLength = 0
		*errMessage = C.CString(err.Error())
		*errLength = C.int(len(err.Error()))
	} else {
		*data = C.CString(string(dataBytes))
		*dataLength = C.int(len(dataBytes))
		*errMessage = nil
		*errLength = 0
	}
}
