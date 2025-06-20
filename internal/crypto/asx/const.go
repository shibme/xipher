package asx

import (
	"fmt"

	"xipher.org/xipher/internal/crypto/ecc"
	"xipher.org/xipher/internal/crypto/kyb"
)

const (
	// PrivateKeyLength is the allowed length of the private key
	PrivateKeyLength = kyb.PrivateKeyLength
	// MinPublicKeyLength is the minimum length allowed for the public key
	MinPublicKeyLength = ecc.KeyLength + 1 // +1 for the algorithm type

	// Algorithm Types
	algoECC   uint8 = 0
	algoKyber uint8 = 1
)

var (
	errInvalidPrivateKeyLength = fmt.Errorf("invalid private key lengths [please use %d bytes]", PrivateKeyLength)
	errInvalidPublicKeyLength  = fmt.Errorf("invalid public key lengths [please use a minimum of %d bytes]", MinPublicKeyLength)
	errInvalidPublicKey        = fmt.Errorf("invalid public key")
	errInvalidAlgorithm        = fmt.Errorf("invalid algorithm")
)
