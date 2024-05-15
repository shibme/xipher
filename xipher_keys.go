package xipher

import (
	"crypto/rand"
	"fmt"

	"dev.shib.me/xipher/internal/asx"
	"dev.shib.me/xipher/internal/xcp"
)

type PrivateKey struct {
	version    uint8
	keyType    uint8
	password   *[]byte
	spec       *kdfSpec
	key        []byte
	symmCipher *xcp.SymmetricCipher
	specKeyMap map[string][]byte
}

// NewPrivateKeyForPassword creates a new private key for the given password.
func NewPrivateKeyForPassword(password []byte) (*PrivateKey, error) {
	spec, err := newSpec()
	if err != nil {
		return nil, err
	}
	return newPrivateKeyForPwdAndSpec(password, spec)
}

// NewPrivateKeyForPasswordAndSpec creates a new private key for the given password and kdf spec.
func NewPrivateKeyForPasswordAndSpec(password []byte, iterations, memory, threads uint8) (*PrivateKey, error) {
	spec, err := newSpec()
	if err != nil {
		return nil, err
	}
	spec.setIterations(iterations).setMemory(memory).setThreads(threads)
	return newPrivateKeyForPwdAndSpec(password, spec)
}

func newPrivateKeyForPwdAndSpec(password []byte, spec *kdfSpec) (privateKey *PrivateKey, err error) {
	if len(password) == 0 {
		return nil, errInvalidPassword
	}
	privateKey = &PrivateKey{
		version:    xipherVersion,
		keyType:    keyTypePwd,
		password:   &password,
		spec:       spec,
		specKeyMap: make(map[string][]byte),
	}
	privateKey.key = privateKey.getKeyForPwdSpec(*spec)
	return privateKey, nil
}

// NewPrivateKey creates a new random private key.
func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, privateKeyRawLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &PrivateKey{
		version: xipherVersion,
		keyType: keyTypeDirect,
		key:     key,
	}, nil
}

// ParsePrivateKey parses the given bytes and returns a corresponding private key. the given bytes must be 33 bytes long.
func ParsePrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != privateKeyFinalLength || key[1] != keyTypeDirect {
		return nil, fmt.Errorf("%s: invalid private key length: expected %d, got %d", "xipher", privateKeyFinalLength, len(key))
	}
	return &PrivateKey{
		version: key[0],
		keyType: keyTypeDirect,
		key:     key[2:],
	}, nil
}

func isPwdBased(keyType uint8) bool {
	return keyType%2 == 1
}

func (privateKey *PrivateKey) getKeyForPwdSpec(spec kdfSpec) (key []byte) {
	specBytes := spec.bytes()
	key = privateKey.specKeyMap[string(specBytes)]
	if len(key) == 0 {
		key = spec.getCipherKey(*privateKey.password)
		privateKey.specKeyMap[string(specBytes)] = key
	}
	return key
}

// Bytes returns the private key as bytes only if it is not password based.
func (privateKey *PrivateKey) Bytes() ([]byte, error) {
	if isPwdBased(privateKey.keyType) {
		return nil, errPrivKeyUnavailableForPwd
	}
	return append([]byte{privateKey.version, privateKey.keyType}, privateKey.key...), nil
}

type PublicKey struct {
	version   uint8
	keyType   uint8
	publicKey *asx.PublicKey
	spec      *kdfSpec
}

// PublicKey returns the public key corresponding to the private key.
func (privateKey *PrivateKey) PublicKey(pq bool) (*PublicKey, error) {
	asxPrivKey, err := asx.ParsePrivateKey(privateKey.key)
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
		version:   privateKey.version,
		keyType:   privateKey.keyType,
		publicKey: asxPubKey,
		spec:      privateKey.spec,
	}, nil
}

// Bytes returns the public key as bytes.
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

// ParsePublicKey parses the given bytes and returns a corresponding public key. the given bytes must be at least 33 bytes long.
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
