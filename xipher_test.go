package xipher

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

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
}

func TestHash(t *testing.T) {
	data := []byte("Hello Xipher!")
	expectedHash := "gde/6Nz8bC+jvIBJlypUcA=="
	calculatedHash := base64.StdEncoding.EncodeToString(Hash(data, 16))
	if calculatedHash != expectedHash {
		t.Errorf("Hash was incorrect, got: %s, want: %s.", calculatedHash, expectedHash)
	}
}
