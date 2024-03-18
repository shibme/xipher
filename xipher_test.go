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

func symmetricKeyTest(t *testing.T, compress bool) {
	data := getTestData()
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Error("Error generating private key", err)
	}
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		t.Error("Error converting private key to bytes", err)
	}
	ciphertext, err := privKey.Encrypt(data, compress)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyFromBytes, err := ParsePrivateKey(privKeyBytes)
	if err != nil {
		t.Error("Error parsing private key", err)
	}
	plaintext, err := privKeyFromBytes.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryStats())
}

func symmetricPwdTest(t *testing.T, compress bool) {
	password := getTestPassword()
	data := getTestData()
	privKey, err := NewPrivateKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	ciphertext, err := privKey.Encrypt(data, compress)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyRecreated, err := NewPrivateKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	plaintext, err := privKeyRecreated.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryStats())
}

func asymmetricKeyTest(t *testing.T, compress, pq bool) {
	data := getTestData()
	privKey, err := NewPrivateKey()
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
	ciphertext, err := publicKey.Encrypt(data, compress)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyFromBytes, err := ParsePrivateKey(privKeyBytes)
	if err != nil {
		t.Error("Error parsing private key", err)
	}
	plaintext, err := privKeyFromBytes.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryStats())
}

func asymmetricPwdTest(t *testing.T, compress, pq bool) {
	password := getTestPassword()
	data := getTestData()
	privKey, err := NewPrivateKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	publicKey, err := privKey.PublicKey(pq)
	if err != nil {
		t.Error("Error generating public key", err)
	}
	ciphertext, err := publicKey.Encrypt(data, compress)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyRecreated, err := NewPrivateKeyForPassword(password)
	if err != nil {
		t.Error("Error generating private key", err)
	}
	plaintext, err := privKeyRecreated.Decrypt(ciphertext)
	if err != nil {
		t.Error("Error decrypting data", err)
	}
	if string(plaintext) != string(data) {
		t.Errorf("Plaintext was incorrect, got: %s, want: %s.", string(plaintext), string(data))
	}
	t.Log(getMemoryStats())
}

func TestSymmetricKeyCompress(t *testing.T) {
	symmetricKeyTest(t, true)
}
func TestSymmetricKeyNoCompress(t *testing.T) {
	symmetricKeyTest(t, false)
}
func TestSymmetricPasswordCompress(t *testing.T) {
	symmetricPwdTest(t, true)
}
func TestSymmetricPasswordNoCompress(t *testing.T) {
	symmetricPwdTest(t, false)
}
func TestAsymmetricKeyCompressPQ(t *testing.T) {
	asymmetricKeyTest(t, true, true)
}
func TestAsymmetricKeyNoCompressPQ(t *testing.T) {
	asymmetricKeyTest(t, false, true)
}
func TestAsymmetricKeyCompressNoPQ(t *testing.T) {
	asymmetricKeyTest(t, true, false)
}
func TestAsymmetricKeyNoCompressNoPQ(t *testing.T) {
	asymmetricKeyTest(t, false, false)
}
func TestAsymmetricPasswordCompressPQ(t *testing.T) {
	asymmetricPwdTest(t, true, true)
}
func TestAsymmetricPasswordNoCompressPQ(t *testing.T) {
	asymmetricPwdTest(t, false, true)
}
func TestAsymmetricPasswordCompressNoPQ(t *testing.T) {
	asymmetricPwdTest(t, true, false)
}
func TestAsymmetricPasswordNoCompressNoPQ(t *testing.T) {
	asymmetricPwdTest(t, false, false)
}
