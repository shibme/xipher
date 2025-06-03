/*
Package xipher provides a curated collection of cryptographic primitives for performing
key/password-based asymmetric encryption with support for post-quantum cryptography.

# Overview

Xipher enables secure data sharing between two parties over an insecure channel using
asymmetric encryption. The sender encrypts data using a public key (usually derived
from a password) and shares the encrypted data with the receiver. The receiver decrypts
the data using the corresponding secret key or password.

# Key Features

• Password-based public key generation using Argon2 key derivation
• Stream cipher with optional compression for memory efficiency
• Post-quantum cryptography support using Kyber1024
• Stream processing for handling large files efficiently
• Base32 encoding for human-readable ciphertext
• Both symmetric and asymmetric encryption modes

# Architecture

The package is built around two main types:

SecretKey: Represents a cryptographic secret key that can be either password-based
or directly generated from random data. It supports both symmetric and asymmetric
encryption operations.

PublicKey: Represents a cryptographic public key for asymmetric encryption.
It contains the actual public key material and associated metadata.

# Key Types

Xipher supports two types of keys:

Direct Keys: Generated from cryptographically secure random data (64 bytes).
These provide maximum entropy and are suitable when key management is handled separately.

Password-based Keys: Derived from passwords using Argon2 key derivation function.
These are more convenient for human use but require secure password practices.

# Encryption Modes

Symmetric Encryption: Uses the secret key directly for encryption/decryption.
This is faster and suitable when the same party encrypts and decrypts.

Asymmetric Encryption: Uses public key for encryption and secret key for decryption.
This enables secure communication between different parties.

# Post-Quantum Cryptography

Xipher supports post-quantum cryptography using the Kyber1024 algorithm, providing
resistance against quantum computer attacks. This can be enabled when generating
public keys by setting the pq parameter to true.

# Basic Usage Examples

## Password-based Encryption

	// Create a secret key from password
	secretKey, err := xipher.NewSecretKeyForPassword([]byte("my-secure-password"))
	if err != nil {
		return err
	}

	// Generate public key (standard ECC)
	publicKey, err := secretKey.PublicKey(false)
	if err != nil {
		return err
	}

	// Encrypt data
	plaintext := []byte("Hello, World!")
	ciphertext, err := publicKey.Encrypt(plaintext, true, true)
	if err != nil {
		return err
	}

	// Decrypt data
	decrypted, err := secretKey.Decrypt(ciphertext)
	if err != nil {
		return err
	}

## Direct Key Generation

	// Generate a random secret key
	secretKey, err := xipher.NewSecretKey()
	if err != nil {
		return err
	}

	// Export key for storage
	keyString, err := secretKey.String()
	if err != nil {
		return err
	}

	// Later, import the key
	importedKey, err := xipher.ParseSecretKeyStr(keyString)
	if err != nil {
		return err
	}

## Post-Quantum Encryption

	// Create secret key
	secretKey, err := xipher.NewSecretKeyForPassword([]byte("quantum-safe-password"))
	if err != nil {
		return err
	}

	// Generate post-quantum public key
	pqPublicKey, err := secretKey.PublicKey(true) // true enables post-quantum
	if err != nil {
		return err
	}

	// Encrypt with post-quantum cryptography
	ciphertext, err := pqPublicKey.Encrypt([]byte("quantum-safe message"), true, true)
	if err != nil {
		return err
	}

## Stream Processing

	// Encrypt large files efficiently
	inputFile, err := os.Open("largefile.txt")
	if err != nil {
		return err
	}
	defer inputFile.Close()

	outputFile, err := os.Create("encrypted.xct")
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Stream encryption
	err = publicKey.EncryptStream(outputFile, inputFile, true, true)
	if err != nil {
		return err
	}

	// Stream decryption
	encryptedFile, err := os.Open("encrypted.xct")
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	decryptedFile, err := os.Create("decrypted.txt")
	if err != nil {
		return err
	}
	defer decryptedFile.Close()

	err = secretKey.DecryptStream(decryptedFile, encryptedFile)
	if err != nil {
		return err
	}

# Key Derivation Parameters

For password-based keys, you can customize the Argon2 parameters:

	// High-security configuration
	secretKey, err := xipher.NewSecretKeyForPasswordAndSpec(
		[]byte("my-password"),
		32,  // iterations (higher = more secure, slower)
		128, // memory in MB (higher = more secure, more memory)
		4,   // threads (higher = faster on multi-core)
	)

# Format Specifications

## Key Formats

Secret keys are encoded with the "XSK_" prefix followed by base32-encoded data.
Public keys are encoded with the "XPK_" prefix followed by base32-encoded data.

## Ciphertext Format

Encrypted data can be output in two formats:
• Binary format: Raw encrypted bytes
• Encoded format: "XCT_" prefix + base32-encoded encrypted data

The encoded format is human-readable and safe for text-based transmission.

# Security Considerations

• Use strong passwords for password-based keys (consider using passphrases)
• Store direct keys securely (they cannot be recovered if lost)
• Consider using post-quantum cryptography for long-term security
• Use compression carefully (it may leak information about plaintext patterns)
• Validate all inputs when parsing keys or ciphertext from external sources

# Error Handling

The package defines several specific error types for different failure modes:
• errInvalidPassword: Empty or invalid password provided
• errInvalidCiphertext: Malformed ciphertext data
• errInvalidPublicKey: Invalid public key format
• errInvalidSecretKey: Invalid secret key format
• errDecryptionFailedPwdRequired: Password required for decryption
• errDecryptionFailedKeyRequired: Direct key required for decryption

# Performance Notes

• Stream processing is more memory-efficient for large data
• Compression reduces ciphertext size but adds CPU overhead
• Post-quantum cryptography increases key sizes and processing time
• Password-based key derivation is intentionally slow for security

# Compatibility

Xipher maintains backward compatibility for encrypted data. Newer versions can
decrypt data encrypted with older versions, but older versions may not support
features introduced in newer versions (like post-quantum cryptography).
*/
package xipher
