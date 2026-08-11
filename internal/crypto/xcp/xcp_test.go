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

// encryptOnly runs data through an encrypting writer and returns the raw ciphertext.
func encryptOnly(t *testing.T, cipher *SymmetricCipher, data []byte, compress bool) []byte {
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
	return buf.Bytes()
}

// encryptDecrypt runs data through an encrypting writer and a decrypting reader
// created from the same cipher and returns the recovered plaintext.
func encryptDecrypt(t *testing.T, cipher *SymmetricCipher, data []byte, compress bool) []byte {
	t.Helper()
	ct := encryptOnly(t, cipher, data, compress)
	r, err := cipher.NewDecryptingReader(bytes.NewReader(ct))
	if err != nil {
		t.Fatalf("error creating decrypting reader: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading decrypted data: %v", err)
	}
	return out
}

// legacyEncrypt reproduces the pre-fix xcp format: one random nonce is
// generated and reused for every block's Seal call. This is the vulnerable
// behavior being fixed, kept here only to prove that ciphertexts already
// produced by older xipher versions still decrypt correctly.
func legacyEncrypt(t *testing.T, cipher *SymmetricCipher, data []byte) []byte {
	t.Helper()
	nonce := randomBytes(t, nonceLength)
	var buf bytes.Buffer
	buf.Write(nonce)
	buf.WriteByte(0) // compress flag: uncompressed
	for len(data) > 0 {
		n := len(data)
		if n > ptBlockSize {
			n = ptBlockSize
		}
		block, rest := data[:n], data[n:]
		data = rest
		ct := (*cipher.aead).Seal(nil, nonce, block, nil)
		buf.Write(ct)
	}
	return buf.Bytes()
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
	// Cover empty data, sub-block, one full block, an exact multiple of the
	// block size (a full block that might also be the last one), and a few
	// blocks plus a remainder.
	sizes := []int{0, 1, 100, ptBlockSize - 1, ptBlockSize, ptBlockSize + 1, 2 * ptBlockSize, 3*ptBlockSize + 123}
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

// TestDistinctCiphertextForIdenticalBlocks is the core regression test for
// the nonce-reuse bug. Identical plaintext blocks must not produce identical
// ciphertext blocks. This would have failed before the fix, since every
// block was sealed with the same reused nonce.
func TestDistinctCiphertextForIdenticalBlocks(t *testing.T) {
	cipher := newTestCipher(t)
	data := bytes.Repeat([]byte{0}, 3*ptBlockSize)

	ct := encryptOnly(t, cipher, data, false)
	body := ct[nonceLength+1:]
	if len(body) != 3*ctBlockSize {
		t.Fatalf("expected %d bytes of ciphertext blocks, got %d", 3*ctBlockSize, len(body))
	}
	blocks := [][]byte{body[:ctBlockSize], body[ctBlockSize : 2*ctBlockSize], body[2*ctBlockSize:]}
	for i := range blocks {
		for j := i + 1; j < len(blocks); j++ {
			if bytes.Equal(blocks[i], blocks[j]) {
				t.Fatalf("identical plaintext blocks %d and %d produced identical ciphertext (nonce reuse)", i, j)
			}
		}
	}

	r, err := cipher.NewDecryptingReader(bytes.NewReader(ct))
	if err != nil {
		t.Fatalf("error creating reader: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("error reading decrypted data: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("round-trip mismatch")
	}
}

func TestTruncatedCiphertextFails(t *testing.T) {
	cipher := newTestCipher(t)
	data := randomBytes(t, 3*ptBlockSize)
	ct := encryptOnly(t, cipher, data, false)

	// Drop the final block. Before the fix, nothing proved this was really
	// the end, so this would quietly decrypt to a truncated plaintext
	// instead of failing.
	truncated := ct[:len(ct)-ctBlockSize]

	r, err := cipher.NewDecryptingReader(bytes.NewReader(truncated))
	if err != nil {
		t.Fatalf("error creating reader: %v", err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected error decrypting truncated ciphertext, got nil")
	}
}

func TestReorderedBlocksFail(t *testing.T) {
	cipher := newTestCipher(t)
	data := randomBytes(t, 3*ptBlockSize)
	ct := encryptOnly(t, cipher, data, false)

	header := ct[:nonceLength+1]
	block0 := ct[nonceLength+1 : nonceLength+1+ctBlockSize]
	block1 := ct[nonceLength+1+ctBlockSize : nonceLength+1+2*ctBlockSize]
	block2 := ct[nonceLength+1+2*ctBlockSize:]

	var swapped bytes.Buffer
	swapped.Write(header)
	swapped.Write(block0)
	swapped.Write(block2) // blocks 1 and 2 swapped
	swapped.Write(block1)

	r, err := cipher.NewDecryptingReader(bytes.NewReader(swapped.Bytes()))
	if err != nil {
		t.Fatalf("error creating reader: %v", err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected error decrypting reordered ciphertext, got nil")
	}
}

// TestLegacyFixedNonceCiphertextStillDecrypts checks that ciphertexts made
// with the old, vulnerable xcp format can still be decrypted, since data
// encrypted before the fix needs to keep working.
func TestLegacyFixedNonceCiphertextStillDecrypts(t *testing.T) {
	cipher := newTestCipher(t)
	sizes := []int{0, 1, 100, ptBlockSize, ptBlockSize + 1, 2 * ptBlockSize, 3*ptBlockSize + 123}
	for _, size := range sizes {
		data := randomBytes(t, size)
		ct := legacyEncrypt(t, cipher, data)

		r, err := cipher.NewDecryptingReader(bytes.NewReader(ct))
		if err != nil {
			t.Fatalf("size=%d: error creating reader: %v", size, err)
		}
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("size=%d: error decrypting legacy-format ciphertext: %v", size, err)
		}
		if !bytes.Equal(out, data) {
			t.Errorf("size=%d: round-trip mismatch decrypting legacy-format ciphertext", size)
		}
	}
}
