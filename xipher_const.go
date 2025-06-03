// Package xipher provides a curated collection of cryptographic primitives
// for performing key/password-based asymmetric encryption.
//
// Xipher allows secure data sharing between two parties over an insecure channel
// using asymmetric encryption. The sender encrypts data using a public key
// (usually derived from a password) and shares the encrypted data with the receiver.
// The receiver decrypts the data using the corresponding secret key or password.
//
// Key features:
//   - Password-based public key generation
//   - Stream cipher with compression support
//   - Post-quantum cryptography using Kyber1024
//   - Stream processing for memory efficiency
//
// Example usage:
//
//	// Create a secret key from password
//	secretKey, err := xipher.NewSecretKeyForPassword([]byte("mypassword"))
//	if err != nil {
//		panic(err)
//	}
//
//	// Generate public key
//	publicKey, err := secretKey.PublicKey(false)
//	if err != nil {
//		panic(err)
//	}
//
//	// Encrypt data
//	plaintext := []byte("Hello, World!")
//	ciphertext, err := publicKey.Encrypt(plaintext, true, true)
//	if err != nil {
//		panic(err)
//	}
//
//	// Decrypt data
//	decrypted, err := secretKey.Decrypt(ciphertext)
//	if err != nil {
//		panic(err)
//	}
package xipher

import (
	"fmt"
	"runtime"

	"xipher.org/xipher/internal/crypto/asx"
)

const (
	// xipherPublicKeyPrefix is the prefix used for public key string encoding.
	xipherPublicKeyPrefix = "XPK_"
	// xipherSecretKeyPrefix is the prefix used for secret key string encoding.
	xipherSecretKeyPrefix = "XSK_"
	// xipherTxtPrefix is the prefix used for encoded ciphertext.
	xipherTxtPrefix = "XCT_"
	// secretKeyStrRegex is the regular expression pattern for validating secret key strings.
	secretKeyStrRegex = "^" + xipherSecretKeyPrefix + "[A-Z2-7]{106}$"

	// secretKeyBaseLength is the length of a secret key when being generated (64 bytes).
	secretKeyBaseLength = asx.PrivateKeyLength
	// secretKeyLength is the length of a secret key when being exported (66 bytes: 64 + 2 header bytes).
	secretKeyLength = secretKeyBaseLength + 2
	// publicKeyMinLength is the minimum length of a public key (varies based on key type).
	publicKeyMinLength = asx.MinPublicKeyLength + 1 // +1 for the key type

	// Default Argon2 parameters for key derivation

	// defaultKdfIterations is the default number of iterations for Argon2 key derivation.
	defaultKdfIterations uint8 = 16
	// defaultKdfMemory is the default memory size in MB for Argon2 key derivation.
	defaultKdfMemory uint8 = 64
	// defaultKdfThreads is the default number of threads for Argon2 key derivation.
	defaultKdfThreads uint8 = 1

	// KDF (Key Derivation Function) constants

	// kdfParamsLenth is the length of KDF parameters (iterations, memory, threads).
	kdfParamsLenth = 3
	// kdfSaltLength is the length of the salt used in key derivation (16 bytes).
	kdfSaltLength = 16
	// kdfSpecLength is the total length of the KDF specification (19 bytes: 3 params + 16 salt).
	kdfSpecLength = kdfParamsLenth + kdfSaltLength

	// Key type constants

	// keyTypeDirect indicates a direct key (not password-based).
	keyTypeDirect uint8 = 0
	// keyTypePwd indicates a password-based key.
	keyTypePwd uint8 = 1

	// Ciphertext type constants

	// ctKeyAsymmetric indicates asymmetric encryption with a direct key.
	ctKeyAsymmetric uint8 = 0
	// ctPwdAsymmetric indicates asymmetric encryption with a password-based key.
	ctPwdAsymmetric uint8 = 1
	// ctKeySymmetric indicates symmetric encryption with a direct key.
	ctKeySymmetric uint8 = 2
	// ctPwdSymmetric indicates symmetric encryption with a password-based key.
	ctPwdSymmetric uint8 = 3

	// keyVersion is the current version of the key format.
	keyVersion uint8 = 0
)

// Common errors returned by xipher operations.
var (
	// errGeneratingSalt is returned when random salt generation fails.
	errGeneratingSalt = fmt.Errorf("%s: error generating salt", "xipher")
	// errInvalidPassword is returned when an invalid password is provided.
	errInvalidPassword = fmt.Errorf("%s: invalid password", "xipher")
	// errInvalidCiphertext is returned when the ciphertext format is invalid.
	errInvalidCiphertext = fmt.Errorf("%s: invalid ciphertext", "xipher")
	// errSecretKeyUnavailableForPwd is returned when trying to export a password-based secret key.
	errSecretKeyUnavailableForPwd = fmt.Errorf("%s: can't derive secret key for passwords", "xipher")
	// errInvalidPublicKey is returned when the public key format is invalid.
	errInvalidPublicKey = fmt.Errorf("%s: invalid public key", "xipher")
	// errInvalidSecretKey is returned when the secret key format is invalid.
	errInvalidSecretKey = fmt.Errorf("%s: invalid secret key", "xipher")
	// errInvalidKDFSpec is returned when the key derivation function specification is invalid.
	errInvalidKDFSpec = fmt.Errorf("%s: invalid kdf spec", "xipher")
	// errDecryptionFailedPwdRequired is returned when password-based decryption is attempted with a direct key.
	errDecryptionFailedPwdRequired = fmt.Errorf("%s: decryption failed, password required", "xipher")
	// errDecryptionFailedKeyRequired is returned when direct key decryption is attempted with a password-based key.
	errDecryptionFailedKeyRequired = fmt.Errorf("%s: decryption failed, key required", "xipher")
)

// Application metadata constants.
const (
	// appName is the application name.
	appName = "Xipher"
	// appNameLowerCase is the lowercase application name.
	appNameLowerCase = "xipher"
	// web is the official website URL.
	web = "https://xipher.org"
	// description is the application description.
	description = "Xipher is a curated collection of cryptographic primitives put together to perform key/password based asymmetric encryption."
	// art is the ASCII art logo.
	art = `
  xxxxxxxxx      xxxxxxxxx  
   xxxxxxxxx    xxxxxxxxx   
    xxxxxxxxx  xxxxxxxxx    
     xxxxxxxxxxxxxxxxxx     
      xxxxxxx  xxxxxxx      
       xxxx      xxxx       
      xxxxxxx  xxxxxxx      
     xxxxxxx    xxxxxxx     
    xxxxxxx      xxxxxxx    
   xxxxxxx        xxxxxxx   
  xxxxxxx          xxxxxxx  
                             `
)

// Build-time variables set by the build system.
var (
	version    = ""
	commitDate = ""
	fullCommit = ""
	releaseURL = ""

	// Info contains application metadata and build information.
	// This structure is populated at build time and provides runtime
	// access to version, build details, and platform information.
	Info = struct {
		AppName     string `json:"appName"`     // Application name
		AppNameLC   string `json:"appNameLC"`   // Application name in lowercase
		Art         string `json:"art"`         // ASCII art logo
		Description string `json:"description"` // Application description
		Version     string `json:"version"`     // Version string
		BuiltAt     string `json:"builtAt"`     // Build timestamp
		ReleaseURL  string `json:"releaseURL"`  // Release URL
		FullCommit  string `json:"fullCommit"`  // Full commit hash
		Web         string `json:"web"`         // Website URL
		Platform    string `json:"platform"`    // Target platform (OS/architecture)
		GoVersion   string `json:"goVersion"`   // Go version used for building
	}{
		AppName:     appName,
		AppNameLC:   appNameLowerCase,
		Art:         art,
		Description: description,
		Version:     version,
		BuiltAt:     commitDate,
		ReleaseURL:  releaseURL,
		FullCommit:  fullCommit,
		Web:         web,
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion:   runtime.Version(),
	}
)
