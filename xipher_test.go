package xipher

import (
	"crypto/rand"
	"fmt"
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

func getTestData() []byte {
	data := make([]byte, 1024*1024)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return data
}

func getTestPassword() []byte {
	password := make([]byte, 100)
	if _, err := rand.Read(password); err != nil {
		panic(err)
	}
	return password
}

func symmetricKeyTest(t *testing.T, compress, encode bool) {
	t.Logf("Testing symmetric key with compress=%v, encode=%v", compress, encode)
	data := getTestData()
	privKey, err := NewSecretKey()
	if err != nil {
		t.Error("Error generating private key", err)
	}
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		t.Error("Error converting private key to bytes", err)
	}
	ciphertext, err := privKey.Encrypt(data, compress, encode)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyFromBytes, err := ParseSecretKey(privKeyBytes)
	if err != nil {
		t.Error("Error parsing private key", err)
	}
	plaintext, err := privKeyFromBytes.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Error("Plaintext does not match with original data")
	}
	t.Log(getMemoryStats())
}

func symmetricPwdTest(t *testing.T, compress, encode bool) {
	t.Logf("Testing symmetric password with compress=%v, encode=%v", compress, encode)
	password := getTestPassword()
	data := getTestData()
	privKey, err := NewSecretKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	ciphertext, err := privKey.Encrypt(data, compress, encode)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyRecreated, err := NewSecretKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	plaintext, err := privKeyRecreated.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Error("Plaintext does not match with original data")
	}
	t.Log(getMemoryStats())
}

func asymmetricKeyTest(t *testing.T, compress, encode, pq bool) {
	t.Logf("Testing asymmetric key with compress=%v, encode=%v, pq=%v", compress, encode, pq)
	data := getTestData()
	privKey, err := NewSecretKey()
	if err != nil {
		t.Error("Error generating private key", err)
	}
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		t.Error("Error converting private key to bytes", err)
	}
	publicKey, err := privKey.PublicKey(pq)
	if err != nil {
		t.Error("Error generating public key", err)
	}
	ciphertext, err := publicKey.Encrypt(data, compress, encode)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyFromBytes, err := ParseSecretKey(privKeyBytes)
	if err != nil {
		t.Error("Error parsing private key", err)
	}
	plaintext, err := privKeyFromBytes.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Error("Plaintext does not match with original data")
	}
	t.Log(getMemoryStats())
}

func asymmetricPwdTest(t *testing.T, compress, encode, pq bool) {
	t.Logf("Testing asymmetric password with compress=%v, encode=%v, pq=%v", compress, encode, pq)
	password := getTestPassword()
	data := getTestData()
	privKey, err := NewSecretKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	publicKey, err := privKey.PublicKey(pq)
	if err != nil {
		t.Error("Error generating public key", err)
	}
	ciphertext, err := publicKey.Encrypt(data, compress, encode)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyRecreated, err := NewSecretKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	plaintext, err := privKeyRecreated.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Error("Plaintext does not match with original data")
	}
	t.Log(getMemoryStats())
}

// Testing with Symmetric Key
func TestSymmetricKey(t *testing.T) {
	tests := []struct {
		compress bool
		encode   bool
	}{
		{false, false},
		{false, true},
		{true, false},
		{true, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("compress=%v/encode=%v", tt.compress, tt.encode), func(t *testing.T) {
			symmetricKeyTest(t, tt.compress, tt.encode)
		})
	}
}

// Testing with Symmetric Password
func TestSymmetricPassword(t *testing.T) {
	tests := []struct {
		compress bool
		encode   bool
	}{
		{false, false},
		{false, true},
		{true, false},
		{true, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("compress=%v/encode=%v", tt.compress, tt.encode), func(t *testing.T) {
			symmetricPwdTest(t, tt.compress, tt.encode)
		})
	}
}

// Testing with Asymmetric Key
func TestAsymmetricKey(t *testing.T) {
	tests := []struct {
		compress bool
		encode   bool
		pq       bool
	}{
		{false, false, false},
		{false, false, true},
		{false, true, false},
		{false, true, true},
		{true, false, false},
		{true, false, true},
		{true, true, false},
		{true, true, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("compress=%v/encode=%v/pq=%v", tt.compress, tt.encode, tt.pq), func(t *testing.T) {
			asymmetricKeyTest(t, tt.compress, tt.encode, tt.pq)
		})
	}
}

// Testing with Asymmetric Password
func TestAsymmetricPassword(t *testing.T) {
	tests := []struct {
		compress bool
		encode   bool
		pq       bool
	}{
		{false, false, false},
		{false, false, true},
		{false, true, false},
		{false, true, true},
		{true, false, false},
		{true, false, true},
		{true, true, false},
		{true, true, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("compress=%v/encode=%v/pq=%v", tt.compress, tt.encode, tt.pq), func(t *testing.T) {
			asymmetricPwdTest(t, tt.compress, tt.encode, tt.pq)
		})
	}
}
