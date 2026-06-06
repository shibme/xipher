package ecc

import (
	"bytes"
	"testing"
)

// TestEncapsulateDecapsulateAgreement verifies that the shared secret produced by
// Encapsulate matches the one recovered by Decapsulate for the matching key pair.
func TestEncapsulateDecapsulateAgreement(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("error deriving public key: %v", err)
	}
	ephPubKey, encSharedKey, err := pubKey.Encapsulate()
	if err != nil {
		t.Fatalf("error encapsulating: %v", err)
	}
	decSharedKey, err := privKey.Decapsulate(ephPubKey)
	if err != nil {
		t.Fatalf("error decapsulating: %v", err)
	}
	if !bytes.Equal(encSharedKey, decSharedKey) {
		t.Fatal("encapsulated and decapsulated shared secrets do not match")
	}
}

// TestEncapsulateFreshEphemeral guards the deliberate no-caching behaviour: each
// Encapsulate call must produce a distinct ephemeral key and shared secret, so the
// hybrid KEM never reuses an ephemeral across encryptions.
func TestEncapsulateFreshEphemeral(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("error deriving public key: %v", err)
	}
	eph1, ss1, err := pubKey.Encapsulate()
	if err != nil {
		t.Fatalf("error on first encapsulate: %v", err)
	}
	eph2, ss2, err := pubKey.Encapsulate()
	if err != nil {
		t.Fatalf("error on second encapsulate: %v", err)
	}
	if bytes.Equal(eph1, eph2) {
		t.Fatal("expected distinct ephemeral public keys across Encapsulate calls")
	}
	if bytes.Equal(ss1, ss2) {
		t.Fatal("expected distinct shared secrets across Encapsulate calls")
	}
}

// TestDecapsulateWrongKeyDiffers ensures decapsulating with an unrelated private
// key yields a different secret rather than the sender's.
func TestDecapsulateWrongKeyDiffers(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("error deriving public key: %v", err)
	}
	ephPubKey, encSharedKey, err := pubKey.Encapsulate()
	if err != nil {
		t.Fatalf("error encapsulating: %v", err)
	}
	otherPriv, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating other private key: %v", err)
	}
	wrongSharedKey, err := otherPriv.Decapsulate(ephPubKey)
	if err != nil {
		t.Fatalf("error decapsulating with wrong key: %v", err)
	}
	if bytes.Equal(encSharedKey, wrongSharedKey) {
		t.Fatal("decapsulating with an unrelated key must not recover the shared secret")
	}
}

func TestDecapsulateInvalidLength(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	for _, n := range []int{0, KeyLength - 1, KeyLength + 1} {
		if _, err := privKey.Decapsulate(make([]byte, n)); err == nil {
			t.Errorf("expected error decapsulating %d-byte ephemeral key, got nil", n)
		}
	}
}
