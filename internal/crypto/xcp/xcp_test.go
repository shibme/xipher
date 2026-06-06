package xcp

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("error generating random bytes: %v", err)
	}
	return b
}

func newTestCipher(t *testing.T) *SymmetricCipher {
	t.Helper()
	cipher, err := New(randomBytes(t, KeyLength))
	if err != nil {
		t.Fatalf("error creating cipher: %v", err)
	}
	return cipher
}

// encryptDecrypt runs data through an encrypting writer and a decrypting reader
// created from the same cipher and returns the recovered plaintext.
func encryptDecrypt(t *testing.T, cipher *SymmetricCipher, data []byte, compress bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := cipher.NewEncryptingWriter(&buf, compress)
	if err != nil {
		t.Fatalf("error creating encrypting writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("error writing data: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("error closing writer: %v", err)
	}
	r, err := cipher.NewDecryptingReader(&buf)
	if err != nil {
		t.Fatalf("error creating decrypting reader: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading decrypted data: %v", err)
	}
	return out
}

func TestNewInvalidKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, KeyLength - 1, KeyLength + 1} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Errorf("expected error for key length %d, got nil", n)
		}
	}
}

func TestRoundTripSizes(t *testing.T) {
	cipher := newTestCipher(t)
	// Cover empty data, sub-block, exactly one block, and several blocks plus a remainder.
	sizes := []int{0, 1, 100, ptBlockSize - 1, ptBlockSize, ptBlockSize + 1, 3*ptBlockSize + 123}
	for _, compress := range []bool{false, true} {
		for _, size := range sizes {
			data := randomBytes(t, size)
			out := encryptDecrypt(t, cipher, data, compress)
			if !bytes.Equal(out, data) {
				t.Errorf("round-trip mismatch for size=%d compress=%v (got %d bytes)", size, compress, len(out))
			}
		}
	}
}

func TestCompressionShrinksCompressibleData(t *testing.T) {
	cipher := newTestCipher(t)
	data := bytes.Repeat([]byte("xipher compresses repetitive data well. "), 4096)

	var plain bytes.Buffer
	pw, err := cipher.NewEncryptingWriter(&plain, false)
	if err != nil {
		t.Fatalf("error creating writer: %v", err)
	}
	if _, err := pw.Write(data); err != nil {
		t.Fatalf("error writing: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("error closing: %v", err)
	}

	var compressed bytes.Buffer
	cw, err := cipher.NewEncryptingWriter(&compressed, true)
	if err != nil {
		t.Fatalf("error creating writer: %v", err)
	}
	if _, err := cw.Write(data); err != nil {
		t.Fatalf("error writing: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("error closing: %v", err)
	}

	if compressed.Len() >= plain.Len() {
		t.Errorf("expected compressed output (%d) smaller than uncompressed (%d)", compressed.Len(), plain.Len())
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	encCipher := newTestCipher(t)
	data := randomBytes(t, 4096)

	var buf bytes.Buffer
	w, err := encCipher.NewEncryptingWriter(&buf, false)
	if err != nil {
		t.Fatalf("error creating writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("error writing: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("error closing: %v", err)
	}

	wrongCipher := newTestCipher(t)
	r, err := wrongCipher.NewDecryptingReader(&buf)
	if err != nil {
		t.Fatalf("error creating reader: %v", err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected authentication failure decrypting with wrong key, got nil")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	cipher := newTestCipher(t)
	data := randomBytes(t, 2048)

	var buf bytes.Buffer
	w, err := cipher.NewEncryptingWriter(&buf, false)
	if err != nil {
		t.Fatalf("error creating writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("error writing: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("error closing: %v", err)
	}

	ct := buf.Bytes()
	// Flip a bit in the AEAD-protected body (past the nonce and compression flag).
	ct[len(ct)-1] ^= 0x01

	r, err := cipher.NewDecryptingReader(bytes.NewReader(ct))
	if err != nil {
		t.Fatalf("error creating reader: %v", err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext, got nil")
	}
}
