package xipher

import (
	"crypto/rand"
	"fmt"
	"regexp"

	"xipher.org/xipher/internal/crypto/asx"
	"xipher.org/xipher/internal/crypto/xcp"
)

// SecretKey represents a cryptographic secret key that can be either password-based
// or directly generated from random data. It supports both symmetric and asymmetric
// encryption operations and maintains internal state for efficient key derivation.
type SecretKey struct {
	version    uint8                // Key format version
	keyType    uint8                // Type of key (direct or password-based)
	password   []byte               // Original password (for password-based keys)
	spec       *kdfSpec             // KDF specification (for password-based keys)
	key        []byte               // Derived or direct key material
	symmCipher *xcp.SymmetricCipher // Cached symmetric cipher instance
	specKeyMap map[string][]byte    // Cache for derived keys with different specs
}

// NewSecretKeyForPassword creates a new secret key derived from the given password.
// It uses default KDF parameters for key derivation (16 iterations, 64MB memory, 1 thread).
//
// This is the most common way to create a secret key for password-based encryption.
// The resulting key can be used for both symmetric and asymmetric operations.
//
// Parameters:
//   - password: The password to derive the key from (must not be empty)
//
// Returns an error if the password is empty or key derivation fails.
//
// Example:
//
//	secretKey, err := xipher.NewSecretKeyForPassword([]byte("my-secure-password"))
//	if err != nil {
//		return err
//	}
func NewSecretKeyForPassword(password []byte) (*SecretKey, error) {
	return NewSecretKeyForPasswordAndSpec(password, defaultKdfIterations, defaultKdfMemory, defaultKdfThreads)
}

// NewSecretKeyForPasswordAndSpec creates a new secret key with custom KDF parameters.
// This allows fine-tuning of the key derivation process for specific security or
// performance requirements.
//
// Parameters:
//   - password: The password to derive the key from (must not be empty)
//   - iterations: Number of Argon2 iterations (higher = more secure, slower)
//   - memory: Memory usage in MB (higher = more secure, more memory)
//   - threads: Number of parallel threads (higher = faster on multi-core systems)
//
// Returns an error if any parameter is invalid or key derivation fails.
//
// Example:
//
//	// High-security configuration: more iterations and memory
//	secretKey, err := xipher.NewSecretKeyForPasswordAndSpec(
//		[]byte("my-secure-password"), 32, 128, 4)
func NewSecretKeyForPasswordAndSpec(password []byte, iterations, memory, threads uint8) (*SecretKey, error) {
	spec, err := newSpec(iterations, memory, threads)
	if err != nil {
		return nil, err
	}
	return newSecretKeyForPwdAndSpec(password, spec)
}

// newSecretKeyForPwdAndSpec creates a password-based secret key with the given spec.
// This is an internal function used by the public constructors.
func newSecretKeyForPwdAndSpec(password []byte, spec *kdfSpec) (secretKey *SecretKey, err error) {
	if len(password) == 0 {
		return nil, errInvalidPassword
	}
	secretKey = &SecretKey{
		version:    keyVersion,
		keyType:    keyTypePwd,
		password:   password,
		spec:       spec,
		specKeyMap: make(map[string][]byte),
	}
	secretKey.key = secretKey.getKeyForPwdSpec(*spec)
	return secretKey, nil
}

// NewSecretKey creates a new secret key from cryptographically secure random data.
// This type of key is not password-based and provides maximum entropy.
// It's suitable for applications where key management is handled separately.
//
// The generated key is 64 bytes of cryptographically secure random data.
//
// Returns an error if random number generation fails.
//
// Example:
//
//	secretKey, err := xipher.NewSecretKey()
//	if err != nil {
//		return err
//	}
//	// Save the key for later use
//	keyString, _ := secretKey.String()
func NewSecretKey() (*SecretKey, error) {
	var seed [secretKeyBaseLength]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return SecretKeyFromSeed(seed)
}

// SecretKeyFromSeed creates a new secret key from the given 64-byte seed.
// This allows creating deterministic keys from known seed material.
//
// Parameters:
//   - seed: Exactly 64 bytes of seed material
//
// The seed should be cryptographically secure random data or derived from
// a secure source. This function does not validate the entropy of the seed.
//
// Example:
//
//	var seed [64]byte
//	copy(seed[:], someSecureRandomData)
//	secretKey, err := xipher.SecretKeyFromSeed(seed)
func SecretKeyFromSeed(seed [secretKeyBaseLength]byte) (*SecretKey, error) {
	return &SecretKey{
		version: keyVersion,
		keyType: keyTypeDirect,
		key:     seed[:],
	}, nil
}

// ParseSecretKey parses a secret key from its binary representation.
// The key must be exactly secretKeyLength bytes and have the correct format.
//
// Parameters:
//   - key: Binary representation of the secret key
//
// Returns an error if the key format is invalid or the length is incorrect.
// Only supports direct (non-password-based) keys.
func ParseSecretKey(key []byte) (*SecretKey, error) {
	if len(key) != secretKeyLength || key[1] != keyTypeDirect {
		return nil, fmt.Errorf("%s: invalid secret key length: expected %d, got %d", "xipher", secretKeyLength, len(key))
	}
	return &SecretKey{
		version: key[0],
		keyType: keyTypeDirect,
		key:     key[2:],
	}, nil
}

// IsSecretKeyStr validates whether a string is a properly formatted secret key string.
// It checks the format but does not validate the cryptographic content.
//
// Parameters:
//   - secretKeyStr: String to validate
//
// Returns true if the string matches the expected secret key format.
//
// Example:
//
//	if xipher.IsSecretKeyStr(keyString) {
//		secretKey, err := xipher.ParseSecretKeyStr(keyString)
//		// ...
//	}
func IsSecretKeyStr(secretKeyStr string) bool {
	return regexp.MustCompile(secretKeyStrRegex).MatchString(secretKeyStr)
}

// ParseSecretKeyStr parses a secret key from its string representation.
// The string must have the correct prefix and format (base32 encoded).
//
// Parameters:
//   - secretKeyStr: String representation of the secret key (e.g., "XSK_...")
//
// Returns an error if the string format is invalid or decoding fails.
//
// Example:
//
//	secretKey, err := xipher.ParseSecretKeyStr("XSK_ABCDEF...")
//	if err != nil {
//		return err
//	}
func ParseSecretKeyStr(secretKeyStr string) (*SecretKey, error) {
	if !IsSecretKeyStr(secretKeyStr) {
		return nil, errInvalidSecretKey
	}
	keyBytes, err := decode(secretKeyStr[len(xipherSecretKeyPrefix):])
	if err != nil {
		return nil, err
	}
	return ParseSecretKey(keyBytes)
}

// isPwdBased returns true if the key type indicates a password-based key.
// This is determined by checking if the key type is odd (password-based types are odd).
func isPwdBased(keyType uint8) bool {
	return keyType%2 == 1
}

// getKeyForPwdSpec derives or retrieves a cached key for the given KDF specification.
// This implements caching to avoid redundant key derivation operations.
func (secretKey *SecretKey) getKeyForPwdSpec(spec kdfSpec) (key []byte) {
	specBytes := spec.bytes()
	key = secretKey.specKeyMap[string(specBytes)]
	if len(key) == 0 {
		key = spec.getCipherKey(secretKey.password)
		secretKey.specKeyMap[string(specBytes)] = key
	}
	return key
}

// Bytes returns the binary representation of the secret key.
// This only works for direct (non-password-based) keys, as password-based
// keys cannot be serialized without compromising security.
//
// The returned bytes include version and type headers followed by the key material.
//
// Returns an error for password-based keys.
//
// Example:
//
//	keyBytes, err := secretKey.Bytes()
//	if err != nil {
//		// Handle password-based key or other error
//		return err
//	}
//	// Store keyBytes securely
func (secretKey *SecretKey) Bytes() ([]byte, error) {
	if isPwdBased(secretKey.keyType) {
		return nil, errSecretKeyUnavailableForPwd
	}
	return append([]byte{secretKey.version, secretKey.keyType}, secretKey.key...), nil
}

// String returns the string representation of the secret key.
// The string format is base32-encoded with the "XSK_" prefix.
// This only works for direct (non-password-based) keys.
//
// Returns an error for password-based keys.
//
// Example:
//
//	keyString, err := secretKey.String()
//	if err != nil {
//		return err
//	}
//	fmt.Println("Secret key:", keyString) // XSK_ABCDEF...
func (secretKey *SecretKey) String() (string, error) {
	secretKeyBytes, err := secretKey.Bytes()
	if err != nil {
		return "", err
	}
	return xipherSecretKeyPrefix + encode(secretKeyBytes), nil
}

// PublicKey represents a cryptographic public key for asymmetric encryption.
// It contains the actual public key material and associated metadata.
type PublicKey struct {
	version   uint8          // Key format version
	keyType   uint8          // Type of key (direct or password-based)
	publicKey *asx.PublicKey // The actual public key for asymmetric operations
	spec      *kdfSpec       // KDF specification (for password-based keys)
}

// PublicKey derives the public key corresponding to this secret key.
// The public key can be used for encryption, while the secret key is needed for decryption.
//
// Parameters:
//   - pq: If true, uses post-quantum cryptography (Kyber1024); if false, uses ECC
//
// Post-quantum cryptography provides resistance against quantum computer attacks
// but results in larger key sizes and ciphertext.
//
// Returns an error if key derivation fails.
//
// Example:
//
//	// Standard ECC public key
//	pubKey, err := secretKey.PublicKey(false)
//
//	// Post-quantum public key
//	pqPubKey, err := secretKey.PublicKey(true)
func (secretKey *SecretKey) PublicKey(pq bool) (*PublicKey, error) {
	asxPrivKey, err := asx.ParsePrivateKey(secretKey.key)
	if err != nil {
		return nil, err
	}
	var asxPubKey *asx.PublicKey
	if pq {
		asxPubKey, err = asxPrivKey.PublicKeyKyber()
	} else {
		asxPubKey, err = asxPrivKey.PublicKeyECC()
	}
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		version:   secretKey.version,
		keyType:   secretKey.keyType,
		publicKey: asxPubKey,
		spec:      secretKey.spec,
	}, nil
}

// Bytes returns the binary representation of the public key.
// The format includes version, type, and optionally KDF specification,
// followed by the actual public key material.
//
// Returns an error if serialization fails.
//
// Example:
//
//	pubKeyBytes, err := publicKey.Bytes()
//	if err != nil {
//		return err
//	}
//	// Store or transmit pubKeyBytes
func (publicKey *PublicKey) Bytes() ([]byte, error) {
	asxPubKeyBytes, err := publicKey.publicKey.Bytes()
	if err != nil {
		return nil, err
	}
	headers := []byte{publicKey.version, publicKey.keyType}
	if isPwdBased(publicKey.keyType) {
		return append(headers, append(publicKey.spec.bytes(), asxPubKeyBytes...)...), nil
	} else {
		return append(headers, asxPubKeyBytes...), nil
	}
}

// String returns the string representation of the public key.
// The string format is base32-encoded with the "XPK_" prefix.
//
// Returns an error if serialization fails.
//
// Example:
//
//	pubKeyString, err := publicKey.String()
//	if err != nil {
//		return err
//	}
//	fmt.Println("Public key:", pubKeyString) // XPK_ABCDEF...
func (publicKey *PublicKey) String() (string, error) {
	pubKeyBytes, err := publicKey.Bytes()
	if err != nil {
		return "", err
	}
	return xipherPublicKeyPrefix + encode(pubKeyBytes), nil
}

// ParsePublicKey parses a public key from its binary representation.
// It supports both direct and password-based public keys.
//
// Parameters:
//   - pubKeyBytes: Binary representation of the public key
//
// Returns an error if the format is invalid or parsing fails.
//
// Example:
//
//	publicKey, err := xipher.ParsePublicKey(keyBytes)
//	if err != nil {
//		return err
//	}
func ParsePublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) < publicKeyMinLength {
		return nil, errInvalidPublicKey
	}
	version := pubKeyBytes[0]
	keyType := pubKeyBytes[1]
	if keyType != keyTypeDirect && keyType != keyTypePwd {
		return nil, errInvalidPublicKey
	}
	keyBytes := pubKeyBytes[2:]
	var spec *kdfSpec
	if keyType == keyTypePwd {
		specBytes := keyBytes[:kdfSpecLength]
		var err error
		if spec, err = parseKdfSpec(specBytes); err != nil {
			return nil, err
		}
		keyBytes = keyBytes[kdfSpecLength:]
	}
	asxPubKey, err := asx.ParsePublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		version:   version,
		keyType:   keyType,
		publicKey: asxPubKey,
		spec:      spec,
	}, nil
}

// IsPubKeyStr validates whether a string is a properly formatted public key string.
// It checks the format but does not validate the cryptographic content.
//
// Parameters:
//   - pubKeyStr: String to validate
//
// Returns true if the string matches the expected public key format.
//
// Example:
//
//	if xipher.IsPubKeyStr(keyString) {
//		publicKey, err := xipher.ParsePublicKeyStr(keyString)
//		// ...
//	}
func IsPubKeyStr(pubKeyStr string) bool {
	return len(pubKeyStr) >= len(xipherPublicKeyPrefix) && pubKeyStr[:len(xipherPublicKeyPrefix)] == xipherPublicKeyPrefix
}

// ParsePublicKeyStr parses a public key from its string representation.
// The string must have the correct prefix and format (base32 encoded).
//
// Parameters:
//   - pubKeyStr: String representation of the public key (e.g., "XPK_...")
//
// Returns an error if the string format is invalid or decoding fails.
//
// Example:
//
//	publicKey, err := xipher.ParsePublicKeyStr("XPK_ABCDEF...")
//	if err != nil {
//		return err
//	}
func ParsePublicKeyStr(pubKeyStr string) (*PublicKey, error) {
	if !IsPubKeyStr(pubKeyStr) {
		return nil, errInvalidPublicKey
	}
	pubKeyBytes, err := decode(pubKeyStr[len(xipherPublicKeyPrefix):])
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(pubKeyBytes)
}
