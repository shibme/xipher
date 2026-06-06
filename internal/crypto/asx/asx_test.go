package asx

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"xipher.org/xipher/internal/crypto/ecc"
	"xipher.org/xipher/internal/crypto/kyb"
)

func getTestData(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, 64*1024+512) // spans more than one xcp block
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("error generating test data: %v", err)
	}
	return data
}

// roundTrip encrypts data with pubKey and decrypts it with privKey, asserting that
// the recovered plaintext matches and that the leading algorithm byte equals wantAlgo.
func roundTrip(t *testing.T, privKey *PrivateKey, pubKey *PublicKey, wantAlgo uint8, compress bool) {
	t.Helper()
	data := getTestData(t)

	var encBuf bytes.Buffer
	w, err := pubKey.NewEncryptingWriter(&encBuf, compress)
	if err != nil {
		t.Fatalf("error creating encrypting writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("error writing data: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("error closing writer: %v", err)
	}

	ct := encBuf.Bytes()
	if len(ct) == 0 || ct[0] != wantAlgo {
		t.Fatalf("expected leading algorithm byte %d, got %v", wantAlgo, ct[:1])
	}

	r, err := privKey.NewDecryptingReader(bytes.NewReader(ct))
	if err != nil {
		t.Fatalf("error creating decrypting reader: %v", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading decrypted data: %v", err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Fatal("decrypted plaintext does not match original data")
	}
}

func TestECCRoundTrip(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKeyECC()
	if err != nil {
		t.Fatalf("error deriving ECC public key: %v", err)
	}
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		t.Fatalf("error serialising public key: %v", err)
	}
	if pubKeyBytes[0] != algoECC {
		t.Fatalf("expected public key algorithm byte %d, got %d", algoECC, pubKeyBytes[0])
	}
	for _, compress := range []bool{false, true} {
		roundTrip(t, privKey, pubKey, algoECC, compress)
	}
}

func TestKyberRoundTrip(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKeyKyber()
	if err != nil {
		t.Fatalf("error deriving Kyber public key: %v", err)
	}
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		t.Fatalf("error serialising public key: %v", err)
	}
	if pubKeyBytes[0] != algoKyber {
		t.Fatalf("expected public key algorithm byte %d, got %d", algoKyber, pubKeyBytes[0])
	}
	for _, compress := range []bool{false, true} {
		roundTrip(t, privKey, pubKey, algoKyber, compress)
	}
}

func TestHybridRoundTrip(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKeyHybrid()
	if err != nil {
		t.Fatalf("error deriving hybrid public key: %v", err)
	}
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		t.Fatalf("error serialising public key: %v", err)
	}
	if pubKeyBytes[0] != algoHybrid {
		t.Fatalf("expected public key algorithm byte %d, got %d", algoHybrid, pubKeyBytes[0])
	}
	// 1 algo byte + X25519 public key (32) + ML-KEM-1024 public key (1568) = 1601 bytes.
	if wantLen := 1 + ecc.KeyLength + kyb.PublicKeyLength; len(pubKeyBytes) != wantLen {
		t.Fatalf("expected hybrid public key length %d, got %d", wantLen, len(pubKeyBytes))
	}
	for _, compress := range []bool{false, true} {
		roundTrip(t, privKey, pubKey, algoHybrid, compress)
	}
}

// TestHybridParsedPublicKeyRoundTrip exercises the encrypt-side path that a caller
// using only the public key bytes would take (ParsePublicKey), proving the wire
// format round-trips independently of the in-memory derived key.
func TestHybridParsedPublicKeyRoundTrip(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKeyHybrid()
	if err != nil {
		t.Fatalf("error deriving hybrid public key: %v", err)
	}
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		t.Fatalf("error serialising public key: %v", err)
	}
	parsedPubKey, err := ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("error parsing hybrid public key: %v", err)
	}
	roundTrip(t, privKey, parsedPubKey, algoHybrid, true)
}

// TestHybridTruncatedCiphertextFails ensures a hybrid record truncated within its
// KEM material (before the symmetric stream) fails to decrypt rather than silently
// succeeding.
func TestHybridTruncatedCiphertextFails(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pubKey, err := privKey.PublicKeyHybrid()
	if err != nil {
		t.Fatalf("error deriving hybrid public key: %v", err)
	}
	data := getTestData(t)
	var encBuf bytes.Buffer
	w, err := pubKey.NewEncryptingWriter(&encBuf, false)
	if err != nil {
		t.Fatalf("error creating encrypting writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("error writing data: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("error closing writer: %v", err)
	}
	// Keep the algo byte and only part of the X25519 ephemeral + ML-KEM ciphertext.
	truncated := encBuf.Bytes()[:1+ecc.KeyLength]
	if _, err := privKey.NewDecryptingReader(bytes.NewReader(truncated)); err == nil {
		t.Fatal("expected error decrypting truncated hybrid ciphertext, got nil")
	}
}
