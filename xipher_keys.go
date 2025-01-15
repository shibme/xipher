package xipher

import (
	"crypto/rand"
	"fmt"

	"xipher.org/xipher/crypto/asx"
	"xipher.org/xipher/crypto/xcp"
)

type SecretKey struct {
	version    uint8
	keyType    uint8
	password   *[]byte
	spec       *kdfSpec
	key        []byte
	symmCipher *xcp.SymmetricCipher
	specKeyMap map[string][]byte
}

// NewSecretKeyForPassword creates a new private key for the given password.
func NewSecretKeyForPassword(password []byte) (*SecretKey, error) {
	return NewSecretKeyForPasswordAndSpec(password, defaultKdfIterations, defaultKdfMemory, defaultKdfThreads)
}

// NewSecretKeyForPasswordAndSpec creates a new private key for the given password and kdf spec.
func NewSecretKeyForPasswordAndSpec(password []byte, iterations, memory, threads uint8) (*SecretKey, error) {
	spec, err := newSpec(iterations, memory, threads)
	if err != nil {
		return nil, err
	}
	return newSecretKeyForPwdAndSpec(password, spec)
}

func newSecretKeyForPwdAndSpec(password []byte, spec *kdfSpec) (secretKey *SecretKey, err error) {
	if len(password) == 0 {
		return nil, errInvalidPassword
	}
	secretKey = &SecretKey{
		version:    keyVersion,
		keyType:    keyTypePwd,
		password:   &password,
		spec:       spec,
		specKeyMap: make(map[string][]byte),
	}
	secretKey.key = secretKey.getKeyForPwdSpec(*spec)
	return secretKey, nil
}

// NewSecretKey creates a new random private key.
func NewSecretKey() (*SecretKey, error) {
	key := make([]byte, secretKeyBaseLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &SecretKey{
		version: keyVersion,
		keyType: keyTypeDirect,
		key:     key,
	}, nil
}

// ParseSecretKey parses the given bytes and returns a corresponding private key.
func ParseSecretKey(key []byte) (*SecretKey, error) {
	if len(key) != secretKeyLength || key[1] != keyTypeDirect {
		return nil, fmt.Errorf("%s: invalid private key length: expected %d, got %d", "xipher", secretKeyLength, len(key))
	}
	return &SecretKey{
		version: key[0],
		keyType: keyTypeDirect,
		key:     key[2:],
	}, nil
}

func isPwdBased(keyType uint8) bool {
	return keyType%2 == 1
}

func (secretKey *SecretKey) getKeyForPwdSpec(spec kdfSpec) (key []byte) {
	specBytes := spec.bytes()
	key = secretKey.specKeyMap[string(specBytes)]
	if len(key) == 0 {
		key = spec.getCipherKey(*secretKey.password)
		secretKey.specKeyMap[string(specBytes)] = key
	}
	return key
}

// Bytes returns the private key as bytes only if it is not password based.
func (secretKey *SecretKey) Bytes() ([]byte, error) {
	if isPwdBased(secretKey.keyType) {
		return nil, errSecretKeyUnavailableForPwd
	}
	return append([]byte{secretKey.version, secretKey.keyType}, secretKey.key...), nil
}

type PublicKey struct {
	version   uint8
	keyType   uint8
	publicKey *asx.PublicKey
	spec      *kdfSpec
}

// PublicKey returns the public key corresponding to the private key.
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

// ParsePublicKey parses the given bytes and returns a corresponding public key.
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
