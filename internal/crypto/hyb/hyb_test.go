package hyb

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"xipher.org/xipher/internal/crypto/ecc"
	"xipher.org/xipher/internal/crypto/kyb"
)

// newKeyPair builds a hybrid public/private key pair from fresh ECC and Kyber keys,
// mirroring how the asx layer assembles a hybrid key from a single seed.
func newKeyPair(t *testing.T) (*PublicKey, *PrivateKey) {
	t.Helper()
	eccPriv, err := ecc.NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating ECC private key: %v", err)
	}
	eccPub, err := eccPriv.PublicKey()
	if err != nil {
		t.Fatalf("error deriving ECC public key: %v", err)
	}
	kybPriv, err := kyb.NewPrivateKey()
	if err != nil {
		t.Fatalf("error generating Kyber private key: %v", err)
	}
	kybPub, err := kybPriv.PublicKey()
	if err != nil {
		t.Fatalf("error deriving Kyber public key: %v", err)
	}
	return NewPublicKey(eccPub, kybPub), NewPrivateKey(eccPriv, kybPriv)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("error generating random bytes: %v", err)
	}
	return b
}

func encrypt(t *testing.T, pubKey *PublicKey, data []byte, compress bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := pubKey.NewEncryptingWriter(&buf, compress)
	if err != nil {
		t.Fatalf("error creating encrypting writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("error writing data: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("error closing writer: %v", err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	pubKey, privKey := newKeyPair(t)
	for _, compress := range []bool{false, true} {
		data := randomBytes(t, 4096)
		ct := encrypt(t, pubKey, data, compress)
		r, err := privKey.NewDecryptingReader(bytes.NewReader(ct))
		if err != nil {
			t.Fatalf("error creating decrypting reader: %v", err)
		}
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("error reading decrypted data: %v", err)
		}
		if !bytes.Equal(out, data) {
			t.Errorf("round-trip mismatch (compress=%v)", compress)
		}
	}
}

func TestPublicKeyBytesRoundTrip(t *testing.T) {
	pubKey, privKey := newKeyPair(t)
	pubKeyBytes := pubKey.Bytes()
	if len(pubKeyBytes) != PublicKeyLength {
		t.Fatalf("expected public key length %d, got %d", PublicKeyLength, len(pubKeyBytes))
	}
	parsed, err := ParsePublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("error parsing hybrid public key: %v", err)
	}
	// The parsed public key (constructed from bytes only) must still encrypt to the
	// holder of the private key.
	data := randomBytes(t, 1024)
	ct := encrypt(t, parsed, data, false)
	r, err := privKey.NewDecryptingReader(bytes.NewReader(ct))
	if err != nil {
		t.Fatalf("error creating decrypting reader: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading decrypted data: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("decryption via parsed public key failed")
	}
}

func TestParsePublicKeyInvalidLength(t *testing.T) {
	for _, n := range []int{0, PublicKeyLength - 1, PublicKeyLength + 1} {
		if _, err := ParsePublicKey(make([]byte, n)); err == nil {
			t.Errorf("expected error parsing %d-byte hybrid public key, got nil", n)
		}
	}
}

// TestTamperedTranscriptFails flips a bit in each segment of the hybrid record
// (X25519 ephemeral, ML-KEM ciphertext, and the symmetric stream) and confirms
// decryption fails. Tampering with the KEM material must change the derived key
// because the combiner binds the full transcript.
func TestTamperedTranscriptFails(t *testing.T) {
	pubKey, privKey := newKeyPair(t)
	data := randomBytes(t, 2048)

	positions := map[string]int{
		"ecc ephemeral":    0,
		"mlkem ciphertext": ecc.KeyLength + 10,
		"symmetric body":   ecc.KeyLength + kyb.CiphertextLength + 30,
	}
	for name, pos := range positions {
		ct := encrypt(t, pubKey, data, false)
		if pos >= len(ct) {
			t.Fatalf("%s: tamper position %d out of range (len %d)", name, pos, len(ct))
		}
		ct[pos] ^= 0x01
		r, err := privKey.NewDecryptingReader(bytes.NewReader(ct))
		if err != nil {
			// Failing at reader construction is an acceptable rejection too.
			continue
		}
		if _, err := io.ReadAll(r); err == nil {
			t.Errorf("%s: expected decryption to fail after tampering, got nil", name)
		}
	}
}

// TestFreshEphemeralPerEncryption ensures two encryptions of the same data under
// the same key produce different records (fresh ECC ephemeral + ML-KEM ciphertext).
func TestFreshEphemeralPerEncryption(t *testing.T) {
	pubKey, _ := newKeyPair(t)
	data := randomBytes(t, 512)
	ct1 := encrypt(t, pubKey, data, false)
	ct2 := encrypt(t, pubKey, data, false)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("expected distinct ciphertexts across encryptions of the same data")
	}
}

// TestWrongPrivateKeyFails confirms an unrelated hybrid private key cannot decrypt.
func TestWrongPrivateKeyFails(t *testing.T) {
	pubKey, _ := newKeyPair(t)
	_, otherPriv := newKeyPair(t)
	ct := encrypt(t, pubKey, randomBytes(t, 1024), false)
	r, err := otherPriv.NewDecryptingReader(bytes.NewReader(ct))
	if err != nil {
		return // rejected at construction
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected decryption with wrong private key to fail, got nil")
	}
}
