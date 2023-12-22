package chacha20poly1305

import (
	"errors"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLength           = chacha20poly1305.KeySize
	CipherTextMinLength = chacha20poly1305.NonceSize
)

var (
	cipherMap map[string]*Cipher = make(map[string]*Cipher)

	errIncorrectCipherTextSize = errors.New("incorrect ciphertext size")
	errIncorrectNonceSize      = errors.New("incorrect nonce size. requires a length of " + strconv.Itoa(chacha20poly1305.NonceSize) + " bytes")
)
