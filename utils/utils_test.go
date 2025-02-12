package utils

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func xipherTextDecryptionTester(t *testing.T, size int) {
	t.Logf("Testing XipherText decryption with data size: %d", size)

	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("Error generating private key: %v", err)
	}

	randData := make([]byte, size)
	if _, err := rand.Read(randData); err != nil {
		t.Fatalf("Error generating random data: %v", err)
	}

	var out bytes.Buffer
	if err = EncryptStream(sk, &out, bytes.NewReader(randData), false, true); err != nil {
		t.Fatalf("Error encrypting data: %v", err)
	}

	t.Logf("Encrypted data len: %d", out.Len())

	if _, err := DecryptData(sk, out.String()); err != nil {
		t.Fatalf("Error decrypting data: %v", err)
	}
}

func TestXipherTextDecryption(t *testing.T) {
	size := 1
	for i := 0; i <= 24; i++ {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			xipherTextDecryptionTester(t, size)
		})
		size *= 2
	}
}
