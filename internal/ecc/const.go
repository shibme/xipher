package ecc

import (
	"errors"
	"strconv"

	"golang.org/x/crypto/curve25519"
)

const (
	// KeyLength is the length of the ECC key.
	KeyLength = curve25519.ScalarSize
)

var (
	errInvalidKeyLength = errors.New("invalid key length [please use " + strconv.Itoa(KeyLength) + " bytes]")

	privateKeyMap map[string]*PrivateKey = make(map[string]*PrivateKey)
	publicKeyMap  map[string]*PublicKey  = make(map[string]*PublicKey)
)
