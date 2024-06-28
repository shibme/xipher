package main

import (
	"C"
)

// XipherNewSecretKey generates a new secret key
//
//export XipherNewSecretKey
func XipherNewSecretKey(secretKey **C.char, secretKeyLength *C.int, errMessage **C.char, errLength *C.int) {
	xipherNewSecretKey(secretKey, secretKeyLength, errMessage, errLength)
}

// XipherGetPublicKey generates a new public key from a secret key or password
//
//export XipherGetPublicKey
func XipherGetPublicKey(secretKeyOrPassword *C.char, quantumSafe C.int, publicKey **C.char, publicKeyLength *C.int, errMessage **C.char, errLength *C.int) {
	xipherGetPublicKey(secretKeyOrPassword, quantumSafe, publicKey, publicKeyLength, errMessage, errLength)
}

// XipherEncryptData encrypts data with a given public key, secret key or password
//
//export XipherEncryptData
func XipherEncryptData(keyOrPassword *C.char, data *C.char, cipherText **C.char, cipherTextLength *C.int, errMessage **C.char, errLength *C.int) {
	xipherEncryptData(keyOrPassword, data, cipherText, cipherTextLength, errMessage, errLength)
}

// XipherDecryptData decrypts data with a given secret key or password
//
//export XipherDecryptData
func XipherDecryptData(secretKeyOrPassword *C.char, cipherText *C.char, data **C.char, dataLength *C.int, errMessage **C.char, errLength *C.int) {
	xipherDecryptData(secretKeyOrPassword, cipherText, data, dataLength, errMessage, errLength)
}

func main() {}
