package xcp

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLength           = chacha20poly1305.KeySize
	nonceLength         = chacha20poly1305.NonceSizeX
	CipherTextMinLength = nonceLength + chacha20poly1305.Overhead
	ptBlockSize         = 64 * 1024
	ctBlockSize         = ptBlockSize + chacha20poly1305.Overhead

	// noncePrefixLength is the part of the nonce that stays the same for a
	// whole message. NewX derives its subkey from just these bytes, so
	// varying only the rest of the nonce per block is enough to make every
	// block's nonce unique.
	noncePrefixLength = 16
	// blockCounterLength is the per-block counter that fills the rest of the
	// nonce, after leaving one byte for the last-block flag.
	blockCounterLength = nonceLength - noncePrefixLength - 1

	notLastBlockFlag byte = 0x00
	lastBlockFlag    byte = 0x01
)

// SymmetricCipher is a wrapper around the AEAD interface from the golang.org/x/crypto/chacha20poly1305 package.
type SymmetricCipher struct {
	aead *cipher.AEAD
}

// New returns a new Cipher instance. If a Cipher instance with the same key has already been created, it will be returned instead.
func New(key []byte) (*SymmetricCipher, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &SymmetricCipher{
		aead: &aead,
	}, nil
}

// buildNonce builds the per-block nonce from the message's random prefix, a
// block counter, and a flag marking the final block. The prefix stays the
// same for every block, so only the counter and flag change. This is used for
// messages spanning more than one block; a message that fits in a single
// partial block is sealed with the stored nonce as-is instead.
func buildNonce(prefix []byte, counter uint64, last bool) []byte {
	if counter >= 1<<(8*blockCounterLength) {
		panic("xcp: block counter overflow")
	}
	nonce := make([]byte, nonceLength)
	copy(nonce, prefix)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	copy(nonce[noncePrefixLength:noncePrefixLength+blockCounterLength], counterBytes[8-blockCounterLength:])
	if last {
		nonce[nonceLength-1] = lastBlockFlag
	} else {
		nonce[nonceLength-1] = notLastBlockFlag
	}
	return nonce
}
