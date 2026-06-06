package hyb

import (
	"crypto/hkdf"
	"crypto/sha256"
	"io"

	"xipher.org/xipher/internal/crypto/ecc"
	"xipher.org/xipher/internal/crypto/kyb"
	"xipher.org/xipher/internal/crypto/xcp"
)

// hybLabel is the domain-separation label for the hybrid KEM combiner. It binds
// the derived key to this specific construction (X-Wing-style, X25519 + ML-KEM-1024,
// HKDF-SHA256). It must differ from any other construction's label.
const hybLabel = "xipher/hybrid-x25519-mlkem1024/v1"

// deriveKey combines the ECC and Kyber shared secrets into a single symmetric key
// using an X-Wing-style HKDF-SHA256 combiner. The transcript (the X25519 ephemeral
// public key, the recipient's X25519 public key, and the ML-KEM ciphertext) is
// bound into the key material so the derived key is tied to this exact exchange.
func deriveKey(eccSS, kybSS, eccEph, recipientEccPub, kybCt []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(eccSS)+len(kybSS)+len(eccEph)+len(recipientEccPub)+len(kybCt))
	ikm = append(ikm, eccSS...)
	ikm = append(ikm, kybSS...)
	ikm = append(ikm, eccEph...)
	ikm = append(ikm, recipientEccPub...)
	ikm = append(ikm, kybCt...)
	return hkdf.Key(sha256.New, ikm, nil, hybLabel, xcp.KeyLength)
}

// NewEncryptingWriter returns a new WriteCloser that encrypts data with the hybrid
// public key and writes to dst. It encapsulates against both the ECC and Kyber
// public keys, writes the X25519 ephemeral public key followed by the ML-KEM
// ciphertext, then streams the symmetric ciphertext under the combined key.
func (publicKey *PublicKey) NewEncryptingWriter(dst io.Writer, compress bool) (io.WriteCloser, error) {
	eccEph, eccSS, err := publicKey.ePub.Encapsulate()
	if err != nil {
		return nil, err
	}
	kybCt, kybSS, err := publicKey.kPub.Encapsulate()
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(eccSS, kybSS, eccEph, publicKey.ePub.Bytes(), kybCt)
	if err != nil {
		return nil, err
	}
	if _, err = dst.Write(eccEph); err != nil {
		return nil, err
	}
	if _, err = dst.Write(kybCt); err != nil {
		return nil, err
	}
	cipher, err := xcp.New(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewEncryptingWriter(dst, compress)
}

// NewDecryptingReader returns a new Reader that reads and decrypts data with the
// hybrid private key from src. It reads the X25519 ephemeral public key and the
// ML-KEM ciphertext, recovers both shared secrets, reconstructs the combined key,
// and streams the decrypted plaintext.
func (privateKey *PrivateKey) NewDecryptingReader(src io.Reader) (io.Reader, error) {
	eccEph := make([]byte, ecc.KeyLength)
	if _, err := io.ReadFull(src, eccEph); err != nil {
		return nil, err
	}
	kybCt := make([]byte, kyb.CiphertextLength)
	if _, err := io.ReadFull(src, kybCt); err != nil {
		return nil, err
	}
	eccSS, err := privateKey.eccPriv.Decapsulate(eccEph)
	if err != nil {
		return nil, err
	}
	kybSS, err := privateKey.kybPriv.Decapsulate(kybCt)
	if err != nil {
		return nil, err
	}
	eccPub, err := privateKey.eccPriv.PublicKey()
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(eccSS, kybSS, eccEph, eccPub.Bytes(), kybCt)
	if err != nil {
		return nil, err
	}
	decrypter, err := xcp.New(key)
	if err != nil {
		return nil, err
	}
	return decrypter.NewDecryptingReader(src)
}
