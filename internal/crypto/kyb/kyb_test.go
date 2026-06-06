package kyb

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, PrivateKeyLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("error generating seed: %v", err)
	}
	return seed
}

// TestEncapsulateDecapsulateAgreement verifies ML-KEM encapsulation against the
// public key produces a shared secret the matching private key recovers.
func TestEncapsulateDecapsulateAgreement(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("error deriving public key: %v", err)
	}
	keyEnc, encSharedKey, err := pubKey.Encapsulate()
	if err != nil {
		t.Fatalf("error encapsulating: %v", err)
	}
	if len(keyEnc) != CiphertextLength {
		t.Fatalf("expected ciphertext length %d, got %d", CiphertextLength, len(keyEnc))
	}
	decSharedKey, err := privKey.Decapsulate(keyEnc)
	if err != nil {
		t.Fatalf("error decapsulating: %v", err)
	}
	if !bytes.Equal(encSharedKey, decSharedKey) {
		t.Fatal("encapsulated and decapsulated shared secrets do not match")
	}
}

// TestSeedDeterminism confirms the same seed yields the same public key, which the
// asx layer relies on to re-derive keys from a stored secret.
func TestSeedDeterminism(t *testing.T) {
	seed := testSeed(t)
	priv1, err := NewPrivateKeyForSeed(seed)
	if err != nil {
		t.Fatalf("error creating first private key: %v", err)
	}
	priv2, err := NewPrivateKeyForSeed(seed)
	if err != nil {
		t.Fatalf("error creating second private key: %v", err)
	}
	pub1, err := priv1.PublicKey()
	if err != nil {
		t.Fatalf("error deriving first public key: %v", err)
	}
	pub2, err := priv2.PublicKey()
	if err != nil {
		t.Fatalf("error deriving second public key: %v", err)
	}
	if !bytes.Equal(pub1.Bytes(), pub2.Bytes()) {
		t.Fatal("the same seed must derive the same public key")
	}
}

func TestNewPrivateKeyForSeedInvalidLength(t *testing.T) {
	for _, n := range []int{0, PrivateKeyLength - 1, PrivateKeyLength + 1} {
		if _, err := NewPrivateKeyForSeed(make([]byte, n)); err == nil {
			t.Errorf("expected error for %d-byte seed, got nil", n)
		}
	}
}

func TestParsePublicKeyRoundTrip(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("error deriving public key: %v", err)
	}
	pubKeyBytes := pubKey.Bytes()
	if len(pubKeyBytes) != PublicKeyLength {
		t.Fatalf("expected public key length %d, got %d", PublicKeyLength, len(pubKeyBytes))
	}
	parsed, err := ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("error parsing public key: %v", err)
	}
	if !bytes.Equal(parsed.Bytes(), pubKeyBytes) {
		t.Fatal("parsed public key bytes do not match original")
	}

	if _, err := ParsePublicKey(make([]byte, PublicKeyLength-1)); err == nil {
		t.Error("expected error parsing short public key, got nil")
	}
}

func TestDecapsulateInvalidCiphertext(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	if _, err := privKey.Decapsulate(make([]byte, CiphertextLength-1)); err == nil {
		t.Error("expected error decapsulating wrong-length ciphertext, got nil")
	}
}
