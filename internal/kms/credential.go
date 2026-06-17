package kms

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"xipher.org/xipher"
)

// entity types used both in the HKDF info string and the API routing.
const (
	entityUser    = "user"
	entityGroup   = "group"
	entityService = "service"
)

// credentialSeedLength is the length of a derived xipher seed (64 bytes).
const credentialSeedLength = 64

// deriveSeed derives a deterministic 64-byte xipher seed for the given entity
// from the master seed using HKDF-SHA256. The info string binds the output to
// the providerID, entity type, and entity id so that the same identity from
// different providers never collides, and the same (providerID, type, id) always
// yields the same seed.
func deriveSeed(master []byte, providerID, entityType, entityID string) ([]byte, error) {
	info := fmt.Sprintf("xkms:%s:%s:%s", providerID, entityType, entityID)
	r := hkdf.New(sha256.New, master, nil, []byte(info))
	seed := make([]byte, credentialSeedLength)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("deriving seed: %w", err)
	}
	return seed, nil
}

// credential is the derived material returned to a caller, encoded per config.
type credential struct {
	Seed string `json:"seed,omitempty"` // base64 of the 64-byte seed
	Key  string `json:"key,omitempty"`  // XSK_ secret key string
	Name string `json:"name,omitempty"`
	ID   string `json:"id"`
	Type string `json:"type"`
}

// secretKeyFromSeed builds a xipher SecretKey from a 64-byte derived seed.
func secretKeyFromSeed(seed []byte) (*xipher.SecretKey, error) {
	if len(seed) != credentialSeedLength {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", credentialSeedLength, len(seed))
	}
	var arr [credentialSeedLength]byte
	copy(arr[:], seed)
	return xipher.SecretKeyFromSeed(arr)
}
