package xipher

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
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
		t.Error("Error generating secret key", err)
	}
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		t.Error("Error converting secret key to bytes", err)
	}
	ciphertext, err := privKey.Encrypt(data, compress, encode)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyFromBytes, err := ParseSecretKey(privKeyBytes)
	if err != nil {
		t.Error("Error parsing secret key", err)
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
		t.Error("Error generating secret key", err)
	}
	ciphertext, err := privKey.Encrypt(data, compress, encode)
	if err != nil {
		t.Error("Error encrypting data", err)
	}
	privKeyRecreated, err := NewSecretKeyForPassword(password)
	if err != nil {
		t.Error("Error generating secret key", err)
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
		t.Error("Error generating secret key", err)
	}
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		t.Error("Error converting secret key to bytes", err)
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
		t.Error("Error parsing secret key", err)
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
		t.Error("Error generating secret key", err)
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
		t.Error("Error generating secret key", err)
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

// =============================================================================
// EXAMPLE FUNCTIONS - Documentation and Usage Examples
// =============================================================================

// Example_basicPasswordEncryption demonstrates basic password-based encryption and decryption.
func Example_basicPasswordEncryption() {
	// Create a secret key from password
	secretKey, err := NewSecretKeyForPassword([]byte("my-secure-password"))
	if err != nil {
		log.Fatal(err)
	}

	// Generate public key for encryption
	publicKey, err := secretKey.PublicKey(false)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt some data
	plaintext := []byte("Hello, World!")
	ciphertext, err := publicKey.Encrypt(plaintext, true, true)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt the data
	decrypted, err := secretKey.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original: %s\n", plaintext)
	fmt.Printf("Decrypted: %s\n", decrypted)
	// Output:
	// Original: Hello, World!
	// Decrypted: Hello, World!
}

// Example_directKeyGeneration demonstrates generating and using direct (non-password-based) keys.
func Example_directKeyGeneration() {
	// Generate a random secret key
	secretKey, err := NewSecretKey()
	if err != nil {
		log.Fatal(err)
	}

	// Export key as string for storage
	keyString, err := secretKey.String()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Key starts with: %s\n", keyString[:4])

	// Later, import the key from string
	importedKey, err := ParseSecretKeyStr(keyString)
	if err != nil {
		log.Fatal(err)
	}

	// Use the imported key
	publicKey, err := importedKey.PublicKey(false)
	if err != nil {
		log.Fatal(err)
	}

	// Test encryption/decryption
	plaintext := []byte("Test message")
	ciphertext, err := publicKey.Encrypt(plaintext, true, true)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := importedKey.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encryption works: %t\n", bytes.Equal(plaintext, decrypted))
	// Output:
	// Key starts with: XSK_
	// Encryption works: true
}

// Example_postQuantumCryptography demonstrates using post-quantum cryptography.
func Example_postQuantumCryptography() {
	// Create secret key
	secretKey, err := NewSecretKeyForPassword([]byte("quantum-safe-password"))
	if err != nil {
		log.Fatal(err)
	}

	// Generate post-quantum public key (Kyber1024)
	pqPublicKey, err := secretKey.PublicKey(true) // true enables post-quantum
	if err != nil {
		log.Fatal(err)
	}

	// Generate standard ECC public key for comparison
	eccPublicKey, err := secretKey.PublicKey(false) // false uses ECC
	if err != nil {
		log.Fatal(err)
	}

	// Get key sizes
	pqKeyBytes, _ := pqPublicKey.Bytes()
	eccKeyBytes, _ := eccPublicKey.Bytes()

	fmt.Printf("Post-quantum key is larger: %t\n", len(pqKeyBytes) > len(eccKeyBytes))

	// Encrypt with post-quantum cryptography
	plaintext := []byte("quantum-safe message")
	ciphertext, err := pqPublicKey.Encrypt(plaintext, true, true)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt with the same secret key
	decrypted, err := secretKey.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Post-quantum encryption works: %t\n", bytes.Equal(plaintext, decrypted))
	// Output:
	// Post-quantum key is larger: true
	// Post-quantum encryption works: true
}

// Example_streamProcessing demonstrates efficient stream processing for large data.
func Example_streamProcessing() {
	// Create secret key
	secretKey, err := NewSecretKeyForPassword([]byte("stream-password"))
	if err != nil {
		log.Fatal(err)
	}

	// Generate public key
	publicKey, err := secretKey.PublicKey(false)
	if err != nil {
		log.Fatal(err)
	}

	// Simulate large data with a string reader
	largeData := strings.Repeat("This is a large file content. ", 1000)
	dataReader := strings.NewReader(largeData)

	// Encrypt using stream processing
	var encryptedBuffer bytes.Buffer
	err = publicKey.EncryptStream(&encryptedBuffer, dataReader, true, true)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt using stream processing
	var decryptedBuffer bytes.Buffer
	err = secretKey.DecryptStream(&decryptedBuffer, &encryptedBuffer)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the data
	decryptedData := decryptedBuffer.String()
	fmt.Printf("Stream processing successful: %t\n", largeData == decryptedData)
	fmt.Printf("Original size: %d bytes\n", len(largeData))
	fmt.Printf("Encrypted data is smaller due to compression: %t\n", encryptedBuffer.Len() < len(largeData))
	// Output:
	// Stream processing successful: true
	// Original size: 30000 bytes
	// Encrypted data is smaller due to compression: true
}

// Example_customKDFParameters demonstrates using custom Argon2 parameters for key derivation.
func Example_customKDFParameters() {
	password := []byte("my-password")

	// Low-security, fast configuration (for testing)
	fastKey, err := NewSecretKeyForPasswordAndSpec(password, 1, 8, 1)
	if err != nil {
		log.Fatal(err)
	}

	// High-security configuration
	secureKey, err := NewSecretKeyForPasswordAndSpec(password, 32, 128, 4)
	if err != nil {
		log.Fatal(err)
	}

	// Both keys work for encryption/decryption
	testData := []byte("test message")

	// Test fast key
	fastPubKey, _ := fastKey.PublicKey(false)
	fastCiphertext, _ := fastPubKey.Encrypt(testData, true, true)
	fastDecrypted, _ := fastKey.Decrypt(fastCiphertext)

	// Test secure key
	securePubKey, _ := secureKey.PublicKey(false)
	secureCiphertext, _ := securePubKey.Encrypt(testData, true, true)
	secureDecrypted, _ := secureKey.Decrypt(secureCiphertext)

	fmt.Printf("Fast key works: %t\n", bytes.Equal(testData, fastDecrypted))
	fmt.Printf("Secure key works: %t\n", bytes.Equal(testData, secureDecrypted))
	fmt.Printf("Different ciphertexts: %t\n", !bytes.Equal(fastCiphertext, secureCiphertext))
	// Output:
	// Fast key works: true
	// Secure key works: true
	// Different ciphertexts: true
}

// Example_symmetricEncryption demonstrates using secret keys for symmetric encryption.
func Example_symmetricEncryption() {
	// Create secret key
	secretKey, err := NewSecretKeyForPassword([]byte("symmetric-password"))
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt directly with secret key (symmetric mode)
	plaintext := []byte("Symmetric encryption is faster!")
	ciphertext, err := secretKey.Encrypt(plaintext, true, true)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt with the same secret key
	decrypted, err := secretKey.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Symmetric encryption works: %t\n", bytes.Equal(plaintext, decrypted))
	// Output:
	// Symmetric encryption works: true
}

// Example_keyValidation demonstrates validating key and ciphertext strings.
func Example_keyValidation() {
	// Generate a secret key
	secretKey, err := NewSecretKey()
	if err != nil {
		log.Fatal(err)
	}

	keyString, _ := secretKey.String()
	publicKey, _ := secretKey.PublicKey(false)
	pubKeyString, _ := publicKey.String()

	// Encrypt some data
	ciphertext, _ := publicKey.Encrypt([]byte("test"), true, true)
	ciphertextString := string(ciphertext)

	// Validate formats
	fmt.Printf("Valid secret key: %t\n", IsSecretKeyStr(keyString))
	fmt.Printf("Valid public key: %t\n", IsPubKeyStr(pubKeyString))
	fmt.Printf("Valid ciphertext: %t\n", IsCTStr(ciphertextString))

	// Test invalid formats
	fmt.Printf("Invalid secret key: %t\n", IsSecretKeyStr("invalid"))
	fmt.Printf("Invalid public key: %t\n", IsPubKeyStr("invalid"))
	fmt.Printf("Invalid ciphertext: %t\n", IsCTStr("invalid"))
	// Output:
	// Valid secret key: true
	// Valid public key: true
	// Valid ciphertext: true
	// Invalid secret key: false
	// Invalid public key: false
	// Invalid ciphertext: false
}

// Example_fileEncryption demonstrates encrypting and decrypting files.
func Example_fileEncryption() {
	// Create a temporary file with test data
	tempFile, err := os.CreateTemp("", "xipher_test_*.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	testData := "This is test file content for encryption."
	tempFile.WriteString(testData)
	tempFile.Close()

	// Create secret key
	secretKey, err := NewSecretKeyForPassword([]byte("file-password"))
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := secretKey.PublicKey(false)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt file
	inputFile, err := os.Open(tempFile.Name())
	if err != nil {
		log.Fatal(err)
	}
	defer inputFile.Close()

	encryptedFile, err := os.CreateTemp("", "xipher_encrypted_*.xct")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(encryptedFile.Name())
	defer encryptedFile.Close()

	err = publicKey.EncryptStream(encryptedFile, inputFile, true, true)
	if err != nil {
		log.Fatal(err)
	}
	encryptedFile.Close()

	// Decrypt file
	encryptedFile, err = os.Open(encryptedFile.Name())
	if err != nil {
		log.Fatal(err)
	}
	defer encryptedFile.Close()

	decryptedFile, err := os.CreateTemp("", "xipher_decrypted_*.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(decryptedFile.Name())
	defer decryptedFile.Close()

	err = secretKey.DecryptStream(decryptedFile, encryptedFile)
	if err != nil {
		log.Fatal(err)
	}
	decryptedFile.Close()

	// Verify content
	decryptedContent, err := os.ReadFile(decryptedFile.Name())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("File encryption successful: %t\n", string(decryptedContent) == testData)
	// Output:
	// File encryption successful: true
}
