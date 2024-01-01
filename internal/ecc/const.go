package ecc

import (
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	// KeyLength is the length of the ECC key.
	KeyLength = curve25519.ScalarSize
)

var (
	errInvalidKeyLength = fmt.Errorf("xipher: invalid key lengths [please use %d bytes]", KeyLength)

	privateKeyMap map[string]*PrivateKey = make(map[string]*PrivateKey)
	publicKeyMap  map[string]*PublicKey  = make(map[string]*PublicKey)
)
