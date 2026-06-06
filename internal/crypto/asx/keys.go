package asx

import (
	"crypto/rand"
	"crypto/sha256"

	"xipher.org/xipher/internal/crypto/ecc"
	"xipher.org/xipher/internal/crypto/hyb"
	"xipher.org/xipher/internal/crypto/kyb"
)

// PrivateKey represents a private key.
type PrivateKey struct {
	key        []byte
	eccPrivKey *ecc.PrivateKey
	kybPrivKey *kyb.PrivateKey
	hybPrivKey *hyb.PrivateKey
	pubKeyECC  *PublicKey
	pubKeyKyb  *PublicKey
	pubKeyHyb  *PublicKey
}

// PublicKey represents a public key.
type PublicKey struct {
	ePub *ecc.PublicKey
	kPub *kyb.PublicKey
	hPub *hyb.PublicKey
}

// Bytes returns the bytes of the private key.
func (privateKey *PrivateKey) Bytes() []byte {
	return privateKey.key
}

// NewPrivateKey generates a new random private key.
func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, PrivateKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return ParsePrivateKey(key)
}

// ParsePrivateKey returns the instance private key for given bytes. Please use exactly 64 bytes.
func ParsePrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != PrivateKeyLength {
		return nil, errInvalidPrivateKeyLength
	}
	return &PrivateKey{
		key: key,
	}, nil
}

func (privateKey *PrivateKey) getEccPrivKey() (*ecc.PrivateKey, error) {
	if privateKey.eccPrivKey == nil {
		eccPrivKeyBytes := sha256.Sum256(privateKey.key)
		eccPrivKey, err := ecc.ParsePrivateKey(eccPrivKeyBytes[:])
		if err != nil {
			return nil, err
		}
		privateKey.eccPrivKey = eccPrivKey
	}
	return privateKey.eccPrivKey, nil
}

func (privateKey *PrivateKey) getKybPrivKey() (*kyb.PrivateKey, error) {
	if privateKey.kybPrivKey == nil {
		kybPrivKey, err := kyb.NewPrivateKeyForSeed(privateKey.key)
		if err != nil {
			return nil, err
		}
		privateKey.kybPrivKey = kybPrivKey
	}
	return privateKey.kybPrivKey, nil
}

func (privateKey *PrivateKey) getHybPrivKey() (*hyb.PrivateKey, error) {
	if privateKey.hybPrivKey == nil {
		eccPrivKey, err := privateKey.getEccPrivKey()
		if err != nil {
			return nil, err
		}
		kybPrivKey, err := privateKey.getKybPrivKey()
		if err != nil {
			return nil, err
		}
		privateKey.hybPrivKey = hyb.NewPrivateKey(eccPrivKey, kybPrivKey)
	}
	return privateKey.hybPrivKey, nil
}

// PublicKey returns the ecc public key corresponding to the private key. The public key is derived from the private key.
func (privateKey *PrivateKey) PublicKeyECC() (*PublicKey, error) {
	if privateKey.pubKeyECC == nil {
		eccPrivKeyBytes := sha256.Sum256(privateKey.key)
		eccPrivKey, err := ecc.ParsePrivateKey(eccPrivKeyBytes[:])
		if err != nil {
			return nil, err
		}
		eccPubKey, err := eccPrivKey.PublicKey()
		if err != nil {
			return nil, err
		}
		privateKey.pubKeyECC = &PublicKey{
			ePub: eccPubKey,
		}
	}
	return privateKey.pubKeyECC, nil
}

// PublicKey returns the kyber public key corresponding to the private key. The public key is derived from the private key.
func (privateKey *PrivateKey) PublicKeyKyber() (*PublicKey, error) {
	if privateKey.pubKeyKyb == nil {
		kybPrivKey, err := kyb.NewPrivateKeyForSeed(privateKey.key)
		if err != nil {
			return nil, err
		}
		kybPubKey, err := kybPrivKey.PublicKey()
		if err != nil {
			return nil, err
		}
		privateKey.pubKeyKyb = &PublicKey{
			kPub: kybPubKey,
		}
	}
	return privateKey.pubKeyKyb, nil
}

// PublicKeyHybrid returns the hybrid (ECC + Kyber) public key corresponding to the private key. The public key is derived from the private key.
func (privateKey *PrivateKey) PublicKeyHybrid() (*PublicKey, error) {
	if privateKey.pubKeyHyb == nil {
		eccPubKey, err := privateKey.PublicKeyECC()
		if err != nil {
			return nil, err
		}
		kybPubKey, err := privateKey.PublicKeyKyber()
		if err != nil {
			return nil, err
		}
		privateKey.pubKeyHyb = &PublicKey{
			hPub: hyb.NewPublicKey(eccPubKey.ePub, kybPubKey.kPub),
		}
	}
	return privateKey.pubKeyHyb, nil
}

// Bytes returns the public key as bytes.
func (publicKey *PublicKey) Bytes() ([]byte, error) {
	if publicKey.ePub != nil {
		return append([]byte{algoECC}, publicKey.ePub.Bytes()...), nil
	} else if publicKey.kPub != nil {
		kybPubKeyBytes := publicKey.kPub.Bytes()
		return append([]byte{algoKyber}, kybPubKeyBytes...), nil
	} else if publicKey.hPub != nil {
		return append([]byte{algoHybrid}, publicKey.hPub.Bytes()...), nil
	} else {
		return nil, errInvalidPublicKey
	}
}

// GetPublicKey returns the instance of public key for given bytes.
func ParsePublicKey(key []byte) (*PublicKey, error) {
	if len(key) < MinPublicKeyLength {
		return nil, errInvalidPublicKeyLength
	}
	switch key[0] {
	case algoECC:
		eccPubKey, err := ecc.ParsePublicKey(key[1:])
		if err != nil {
			return nil, err
		}
		return &PublicKey{
			ePub: eccPubKey,
		}, nil
	case algoKyber:
		kybPubKey, err := kyb.ParsePublicKey(key[1:])
		if err != nil {
			return nil, err
		}
		return &PublicKey{
			kPub: kybPubKey,
		}, nil
	case algoHybrid:
		hybPubKey, err := hyb.ParsePublicKey(key[1:])
		if err != nil {
			return nil, err
		}
		return &PublicKey{
			hPub: hybPubKey,
		}, nil
	default:
		return nil, errInvalidPublicKey
	}
}
