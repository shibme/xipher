package xipher

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"testing"
)

func getMemoryUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	mb := float64(m.Alloc) / (1024 * 1024)
	return fmt.Sprintf("Memory usage: %.2f MB", mb)
}

func TestPasswordSymmetricCipher(t *testing.T) {
	password := make([]byte, 14)
	if _, err := rand.Read(password); err != nil {
		t.Error("Error generating random password", err)
	}
	privKey, err := NewPrivateKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key for password", err)
	}
	data := []byte("Hello Xipher!")
	uncompressedCiphertext, err := privKey.Encrypt(data, false)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err := privKey.Decrypt(uncompressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	compressedCiphertext, err := privKey.Encrypt(data, true)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err = privKey.Decrypt(compressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryUsage())
}

func TestKeySymmetricCipher(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Error("Error generating random key", err)
	}
	privKey, err := ParsePrivateKey(key)
	if err != nil {
		t.Error("Error parsing private key", err)
	}
	data := []byte("Hello Xipher!")
	uncompressedCiphertext, err := privKey.Encrypt(data, false)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err := privKey.Decrypt(uncompressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	compressedCiphertext, err := privKey.Encrypt(data, true)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err = privKey.Decrypt(compressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryUsage())
}
func TestPasswordAsymmetricCipher(t *testing.T) {
	password := make([]byte, 14)
	if _, err := rand.Read(password); err != nil {
		t.Error("Error generating random password", err)
	}
	privKey, err := NewPrivateKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key for password", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Error("Error generating public key", err)
	}
	data := []byte("Hello Xipher!")
	uncompressedCiphertext, err := pubKey.Encrypt(data, false)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err := privKey.Decrypt(uncompressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	compressedCiphertext, err := pubKey.Encrypt(data, true)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err = privKey.Decrypt(compressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryUsage())
}

func TestKeyAsymmetricCipher(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Error("Error generating random key", err)
	}
	privKey, err := ParsePrivateKey(key)
	if err != nil {
		t.Error("Error parsing private key", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Error("Error generating public key", err)
	}
	data := []byte("Hello Xipher!")
	uncompressedCiphertext, err := pubKey.Encrypt(data, false)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err := privKey.Decrypt(uncompressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	compressedCiphertext, err := pubKey.Encrypt(data, true)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	plaintext, err = privKey.Decrypt(compressedCiphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryUsage())
}

func TestFileEncryption(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Error("Error generating private key", err)
	}

	// Generating Test Data
	ptFile, err := os.CreateTemp("", "xipher")
	if err != nil {
		t.Error("Error creating temp file", err)
	}
	block := make([]byte, 1024*1024)
	for i := 0; i < 32; i++ {
		_, err := rand.Read(block)
		if err != nil {
			t.Error("Error generating random data", err)
		}
		ptFile.Write(block)
	}
	ptFile.Close()

	// Encrypting Test Data
	ptFile, err = os.Open(ptFile.Name())
	if err != nil {
		t.Error("Error opening test file for PT", err)
	}
	ctFile, err := os.CreateTemp("", "xipher")
	if err != nil {
		t.Error("Error creating temp file for CT", err)
	}
	if err := privKey.EncryptStream(ctFile, ptFile, false); err != nil {
		t.Error("Error encrypting data", err)
	}
	ctFile.Close()
	ptFile.Close()

	// Decrypting Test Data
	ctFile, err = os.Open(ctFile.Name())
	if err != nil {
		t.Error("Error opening test file for CT", err)
	}
	ptFile, err = os.CreateTemp("", "xipher")
	if err != nil {
		t.Error("Error creating temp file for PT", err)
	}
	if err := privKey.DecryptStream(ptFile, ctFile); err != nil {
		t.Error("Error decrypting data", err)
	}
	ptFile.Close()
	ctFile.Close()

	t.Log(getMemoryUsage())
}

func TestHash(t *testing.T) {
	data := []byte("Hello Xipher!")
	expectedHash := "gde/6Nz8bC+jvIBJlypUcA=="
	calculatedHash := base64.StdEncoding.EncodeToString(Hash(data, 16))
	if calculatedHash != expectedHash {
		t.Errorf("Hash was incorrect, got: %s, want: %s.", calculatedHash, expectedHash)
	}

	t.Log(getMemoryUsage())
}
