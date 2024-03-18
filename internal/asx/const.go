package asx

import (
	"fmt"

	"dev.shib.me/xipher/internal/ecc"
	"dev.shib.me/xipher/internal/kyb"
)

const (
	// PrivateKeyLength is the allowed length of the private key
	PrivateKeyLength = kyb.PrivateKeyLength
	// MinPublicKeyLength is the minimum length allowed for the public key
	MinPublicKeyLength = ecc.KeyLength + 1

	// Algorithm Types
	AlgoECC   uint8 = 0
	AlgoKyber uint8 = 1
)

var (
	errInvalidPrivateKeyLength = fmt.Errorf("xipher: invalid private key lengths [please use %d bytes]", PrivateKeyLength)
	errInvalidPublicKeyLength  = fmt.Errorf("xipher: invalid public key lengths [please use a minimum of %d bytes]", MinPublicKeyLength)
	errInvalidPublicKey        = fmt.Errorf("xipher: invalid public key")
	errInvalidAlgorithm        = fmt.Errorf("xipher: invalid algorithm")
)
