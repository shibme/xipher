package xipher

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func getMemoryStats() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Alloc = %v MB", m.Alloc/1024/1024))
	sb.WriteString(fmt.Sprintf("\tTotalAlloc = %v MB", m.TotalAlloc/1024/1024))
	sb.WriteString(fmt.Sprintf("\tSys = %v MB", m.Sys/1024/1024))
	sb.WriteString(fmt.Sprintf("\tNumGC = %v\n", m.NumGC))
	return sb.String()
}

func TestKeyXipher(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Error("Error parsing private key", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Error("Error generating public key", err)
	}
	data := []byte("Hello World!")
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
	t.Log(getMemoryStats())
}

func TestFileEncryption(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Error("Error generating private key", err)
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Error("Error generating public key", err)
	}

	// Generating Test Data
	ptFile, err := os.CreateTemp("", "xipher")
	if err != nil {
		t.Error("Error creating temp file", err)
	}
	block := make([]byte, 1024*1024)
	for i := 0; i < 10; i++ {
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
	if err := pubKey.EncryptStream(ctFile, ptFile, false); err != nil {
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

	t.Log(getMemoryStats())
}

func TestPasswordXipher(t *testing.T) {
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
	data := []byte("Hello World!")
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
	t.Log(getMemoryStats())
}
