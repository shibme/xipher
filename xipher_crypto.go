package xipher

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"xipher.org/xipher/internal/crypto/asx"
	"xipher.org/xipher/internal/crypto/xcp"
)

// newVariableKeySymmCipher creates a symmetric cipher from a key of variable length.
// If the key is exactly secretKeyBaseLength bytes, it hashes it with SHA256 to get a 32-byte key.
// This allows using both 32-byte and 64-byte keys for symmetric encryption.
func newVariableKeySymmCipher(key []byte) (*xcp.SymmetricCipher, error) {
	if len(key) == secretKeyBaseLength {
		keySum := sha256.Sum256(key)
		key = keySum[:]
	}
	return xcp.New(key)
}

// IsCTStr validates whether a string is a properly formatted ciphertext string.
// It checks if the string starts with the xipher ciphertext prefix "XCT_".
//
// Parameters:
//   - str: String to validate
//
// Returns true if the string appears to be xipher-encoded ciphertext.
//
// Example:
//
//	if xipher.IsCTStr(ciphertext) {
//		// This is xipher-encoded ciphertext
//		decrypted, err := secretKey.Decrypt([]byte(ciphertext))
//	}
func IsCTStr(str string) bool {
	return len(str) >= len(xipherTxtPrefix) && str[:len(xipherTxtPrefix)] == xipherTxtPrefix
}

// NewEncryptingWriter creates a streaming writer that encrypts data using the secret key
// in symmetric mode. The writer encrypts data as it's written and outputs the result to dst.
//
// Parameters:
//   - dst: Destination writer for encrypted output
//   - compress: If true, compresses data before encryption (reduces size)
//   - encode: If true, base32-encodes the output with "XCT_" prefix
//
// Returns a WriteCloser that must be closed to finalize encryption.
// The Close() method is essential for proper encryption completion.
//
// Example:
//
//	var buf bytes.Buffer
//	writer, err := secretKey.NewEncryptingWriter(&buf, true, true)
//	if err != nil {
//		return err
//	}
//	writer.Write([]byte("Hello, World!"))
//	writer.Close() // Essential for proper encryption
//	ciphertext := buf.Bytes()
func (secretKey *SecretKey) NewEncryptingWriter(dst io.Writer, compress, encode bool) (writer io.WriteCloser, err error) {
	var encodeWriteCloser io.WriteCloser
	if encode {
		dst.Write([]byte(xipherTxtPrefix))
		encodeWriteCloser = encoder(dst)
		dst = encodeWriteCloser
	}
	if isPwdBased(secretKey.keyType) {
		if _, err := dst.Write([]byte{ctPwdSymmetric}); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write ciphertext type", "xipher")
		}
		if _, err := dst.Write(secretKey.spec.bytes()); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write kdf spec", "xipher")
		}
	} else {
		if _, err := dst.Write([]byte{ctKeySymmetric}); err != nil {
			return nil, fmt.Errorf("%s: encrypter failed to write ciphertext type", "xipher")
		}
	}
	if secretKey.symmCipher == nil {
		if secretKey.symmCipher, err = newVariableKeySymmCipher(secretKey.key); err != nil {
			return nil, err
		}
	}
	encryptingWriteCloser, err := secretKey.symmCipher.NewEncryptingWriter(dst, compress)
	if err != nil {
		return nil, err
	}
	if encodeWriteCloser != nil {
		return &dualWriteCloser{encryptingWriteCloser, encodeWriteCloser}, nil
	}
	return encryptingWriteCloser, nil
}

// EncryptStream encrypts data from src and writes the encrypted result to dst
// using the secret key in symmetric mode. This is efficient for large data streams.
//
// Parameters:
//   - dst: Destination writer for encrypted output
//   - src: Source reader for plaintext input
//   - compress: If true, compresses data before encryption (reduces size)
//   - encode: If true, base32-encodes the output with "XCT_" prefix
//
// Returns an error if encryption fails at any stage.
//
// Example:
//
//	file, _ := os.Open("largefile.txt")
//	defer file.Close()
//	var encrypted bytes.Buffer
//	err := secretKey.EncryptStream(&encrypted, file, true, true)
func (secretKey *SecretKey) EncryptStream(dst io.Writer, src io.Reader, compress, encode bool) (err error) {
	encryptedWriter, err := secretKey.NewEncryptingWriter(dst, compress, encode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptedWriter, src); err != nil {
		return err
	}
	return encryptedWriter.Close()
}

// Encrypt encrypts the given data using the secret key in symmetric mode.
// This is a convenience method for encrypting small amounts of data in memory.
//
// Parameters:
//   - data: Plaintext data to encrypt
//   - compress: If true, compresses data before encryption (reduces size)
//   - encode: If true, base32-encodes the output with "XCT_" prefix
//
// Returns the encrypted ciphertext or an error if encryption fails.
//
// Example:
//
//	plaintext := []byte("Hello, World!")
//	ciphertext, err := secretKey.Encrypt(plaintext, true, true)
//	if err != nil {
//		return err
//	}
//	// ciphertext is now encrypted and optionally compressed/encoded
func (secretKey *SecretKey) Encrypt(data []byte, compress, encode bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = secretKey.EncryptStream(&buf, bytes.NewReader(data), compress, encode); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NewEncryptingWriter creates a streaming writer that encrypts data using the public key
// in asymmetric mode. The writer encrypts data as it's written and outputs the result to dst.
//
// Parameters:
//   - dst: Destination writer for encrypted output
//   - compress: If true, compresses data before encryption (reduces size)
//   - encode: If true, base32-encodes the output with "XCT_" prefix
//
// Returns a WriteCloser that must be closed to finalize encryption.
// The Close() method is essential for proper encryption completion.
//
// Example:
//
//	var buf bytes.Buffer
//	writer, err := publicKey.NewEncryptingWriter(&buf, true, true)
//	if err != nil {
//		return err
//	}
//	writer.Write([]byte("Hello, World!"))
//	writer.Close() // Essential for proper encryption
//	ciphertext := buf.Bytes()
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compress, encode bool) (writer io.WriteCloser, err error) {
	var encodeWriteCloser io.WriteCloser
	if encode {
		dst.Write([]byte(xipherTxtPrefix))
		encodeWriteCloser = encoder(dst)
		dst = encodeWriteCloser
	}
	if isPwdBased(publicKey.keyType) {
		if _, err := dst.Write([]byte{ctPwdAsymmetric}); err != nil {
			return nil, err
		}
		if _, err := dst.Write(publicKey.spec.bytes()); err != nil {
			return nil, err
		}
	} else {
		if _, err := dst.Write([]byte{ctKeyAsymmetric}); err != nil {
			return nil, err
		}
	}
	encryptingWriteCloser, err := publicKey.publicKey.NewEncryptingWriter(dst, compress)
	if err != nil {
		return nil, err
	}
	if encodeWriteCloser != nil {
		return &dualWriteCloser{encryptingWriteCloser, encodeWriteCloser}, nil
	}
	return encryptingWriteCloser, nil
}

// EncryptStream encrypts data from src and writes the encrypted result to dst
// using the public key in asymmetric mode. This is efficient for large data streams.
//
// Parameters:
//   - dst: Destination writer for encrypted output
//   - src: Source reader for plaintext input
//   - compress: If true, compresses data before encryption (reduces size)
//   - encode: If true, base32-encodes the output with "XCT_" prefix
//
// Returns an error if encryption fails at any stage.
//
// Example:
//
//	file, _ := os.Open("largefile.txt")
//	defer file.Close()
//	var encrypted bytes.Buffer
//	err := publicKey.EncryptStream(&encrypted, file, true, true)
func (publicKey *PublicKey) EncryptStream(dst io.Writer, src io.Reader, compress, encode bool) (err error) {
	encryptedWriter, err := publicKey.NewEncryptingWriter(dst, compress, encode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(encryptedWriter, src); err != nil {
		return err
	}
	return encryptedWriter.Close()
}

// Encrypt encrypts the given data using the public key in asymmetric mode.
// This is a convenience method for encrypting small amounts of data in memory.
//
// Parameters:
//   - data: Plaintext data to encrypt
//   - compress: If true, compresses data before encryption (reduces size)
//   - encode: If true, base32-encodes the output with "XCT_" prefix
//
// Returns the encrypted ciphertext or an error if encryption fails.
//
// Example:
//
//	plaintext := []byte("Hello, World!")
//	ciphertext, err := publicKey.Encrypt(plaintext, true, true)
//	if err != nil {
//		return err
//	}
//	// ciphertext is now encrypted and optionally compressed/encoded
func (publicKey *PublicKey) Encrypt(data []byte, compress, encode bool) (ciphertext []byte, err error) {
	var buf bytes.Buffer
	if err = publicKey.EncryptStream(&buf, bytes.NewReader(data), compress, encode); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// newPlainDecryptingReader creates a reader that decrypts data without base32 decoding.
// This is used internally when the ciphertext is in binary format (not base32-encoded).
// It handles both symmetric and asymmetric decryption based on the ciphertext type.
func (secretKey *SecretKey) newPlainDecryptingReader(src io.Reader) (io.Reader, error) {
	ctTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(src, ctTypeBytes); err != nil {
		return nil, fmt.Errorf("%s: decrypter failed to read ciphertext type", "xipher")
	}
	var ctType uint8 = ctTypeBytes[0]
	key := secretKey.key
	switch ctType {
	case ctKeyAsymmetric, ctKeySymmetric:
		if isPwdBased(secretKey.keyType) {
			return nil, errDecryptionFailedKeyRequired
		}
	case ctPwdAsymmetric, ctPwdSymmetric:
		if !isPwdBased(secretKey.keyType) {
			return nil, errDecryptionFailedPwdRequired
		}
		specBytes := make([]byte, kdfSpecLength)
		if _, err := io.ReadFull(src, specBytes); err != nil {
			return nil, fmt.Errorf("%s: decrypter failed to read kdf spec", "xipher")
		}
		spec, err := parseKdfSpec(specBytes)
		if err != nil {
			return nil, err
		}
		key = secretKey.getKeyForPwdSpec(*spec)
	default:
		return nil, errInvalidCiphertext
	}
	switch ctType {
	case ctKeyAsymmetric, ctPwdAsymmetric:
		asxPrivKey, err := asx.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		return asxPrivKey.NewDecryptingReader(src)
	case ctKeySymmetric, ctPwdSymmetric:
		symmCipher, err := newVariableKeySymmCipher(key)
		if err != nil {
			return nil, err
		}
		return symmCipher.NewDecryptingReader(src)
	}
	return nil, errInvalidCiphertext
}

// NewDecryptingReader creates a streaming reader that decrypts data from src.
// It automatically detects whether the input is base32-encoded (with "XCT_" prefix)
// or in binary format, and handles both symmetric and asymmetric decryption.
//
// Parameters:
//   - src: Source reader containing encrypted data
//
// Returns a reader that provides decrypted plaintext data.
//
// Example:
//
//	encryptedFile, _ := os.Open("encrypted.txt")
//	defer encryptedFile.Close()
//	decryptedReader, err := secretKey.NewDecryptingReader(encryptedFile)
//	if err != nil {
//		return err
//	}
//	// Read decrypted data from decryptedReader
//	plaintext, _ := io.ReadAll(decryptedReader)
func (secretKey *SecretKey) NewDecryptingReader(src io.Reader) (io.Reader, error) {
	pr := &peekableReader{
		r:   src,
		buf: bytes.Buffer{},
	}
	ctPrefix, err := pr.Peek(len(xipherTxtPrefix))
	if err != nil {
		return nil, err
	}
	if string(ctPrefix) != xipherTxtPrefix {
		return secretKey.newPlainDecryptingReader(pr)
	}
	pr.Discard(len(xipherTxtPrefix))
	return secretKey.newPlainDecryptingReader(decoder(pr))
}

// DecryptStream decrypts data from src and writes the decrypted result to dst.
// This is efficient for large encrypted data streams and automatically handles
// both base32-encoded and binary ciphertext formats.
//
// Parameters:
//   - dst: Destination writer for decrypted output
//   - src: Source reader containing encrypted data
//
// Returns an error if decryption fails at any stage.
//
// Example:
//
//	encryptedFile, _ := os.Open("encrypted.txt")
//	defer encryptedFile.Close()
//	decryptedFile, _ := os.Create("decrypted.txt")
//	defer decryptedFile.Close()
//	err := secretKey.DecryptStream(decryptedFile, encryptedFile)
func (secretKey *SecretKey) DecryptStream(dst io.Writer, src io.Reader) (err error) {
	decryptedReader, err := secretKey.NewDecryptingReader(src)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, decryptedReader)
	return err
}

// Decrypt decrypts the given ciphertext and returns the original plaintext.
// This is a convenience method for decrypting small amounts of data in memory.
// It automatically handles both base32-encoded and binary ciphertext formats.
//
// Parameters:
//   - ciphertext: Encrypted data to decrypt
//
// Returns the decrypted plaintext or an error if decryption fails.
//
// Example:
//
//	// Decrypt data encrypted with the corresponding public key
//	plaintext, err := secretKey.Decrypt(ciphertext)
//	if err != nil {
//		return err
//	}
//	fmt.Println("Decrypted:", string(plaintext))
func (secretKey *SecretKey) Decrypt(ciphertext []byte) (data []byte, err error) {
	var buf bytes.Buffer
	if err = secretKey.DecryptStream(&buf, bytes.NewReader(ciphertext)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
