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
	errInvalidPrivateKeyLength = fmt.Errorf("%s: invalid private key lengths [please use %d bytes]", "xipher", PrivateKeyLength)
	errInvalidPublicKeyLength  = fmt.Errorf("%s: invalid public key lengths [please use a minimum of %d bytes]", "xipher", MinPublicKeyLength)
	errInvalidPublicKey        = fmt.Errorf("%s: invalid public key", "xipher")
	errInvalidAlgorithm        = fmt.Errorf("%s: invalid algorithm", "xipher")
)
