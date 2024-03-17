package xipher

import (
	"crypto/rand"
	"fmt"

	"dev.shib.me/xipher/internal/ecc"
	"dev.shib.me/xipher/internal/xcp"
)

type PrivateKey struct {
	keyType    uint8
	password   *[]byte
	spec       *kdfSpec
	key        []byte
	symmCipher *xcp.SymmetricCipher
	publicKey  *PublicKey
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

func newPrivateKeyForPwdAndSpec(password []byte, spec *kdfSpec) (*PrivateKey, error) {
	if len(password) == 0 {
		return nil, errInvalidPassword
	}
	privateKey := &PrivateKey{
		keyType:    keyTypePwd,
		password:   &password,
		spec:       spec,
		key:        spec.getCipherKey(password),
		specKeyMap: make(map[string][]byte),
	}
	privateKey.specKeyMap[string(privateKey.spec.bytes())] = privateKey.key
	return privateKey, nil
}

// NewPrivateKey creates a new random private key.
func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &PrivateKey{
		keyType: keyTypeDirect,
		key:     key,
	}, nil
}

// ParsePrivateKey parses the given bytes and returns a corresponding private key. the given bytes must be 33 bytes long.
func ParsePrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) < privateKeyMinLength || key[0] != keyTypeDirect {
		return nil, fmt.Errorf("%s: invalid private key length: expected %d, got %d", "xipher", privateKeyMinLength, len(key))
	}
	return &PrivateKey{
		keyType: keyTypeDirect,
		key:     key[1:],
	}, nil
}

func (privateKey *PrivateKey) isPwdBased() bool {
	return privateKey.keyType%2 == 1
}

// Bytes returns the private key as bytes only if it is not password based.
func (privateKey *PrivateKey) Bytes() ([]byte, error) {
	if privateKey.isPwdBased() {
		return nil, errPrivKeyUnavailableForPwd
	}
	return append([]byte{privateKey.keyType}, privateKey.key...), nil
}

// PublicKey returns the public key corresponding to the private key.
func (privateKey *PrivateKey) PublicKey() (*PublicKey, error) {
	if privateKey.publicKey == nil {
		eccPrivKey, err := ecc.GetPrivateKey(privateKey.key)
		if err != nil {
			return nil, err
		}
		eccPubKey, err := eccPrivKey.PublicKey()
		if err != nil {
			return nil, err
		}
		privateKey.publicKey = &PublicKey{
			keyType:   privateKey.keyType,
			publicKey: eccPubKey,
			spec:      privateKey.spec,
		}
	}
	return privateKey.publicKey, nil
}

type PublicKey struct {
	keyType   uint8
	publicKey *ecc.PublicKey
	spec      *kdfSpec
}

// ParsePublicKey parses the given bytes and returns a corresponding public key. the given bytes must be at least 33 bytes long.
func ParsePublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) < publicKeyMinLength {
		return nil, errInvalidPublicKey
	}
	keyType := pubKeyBytes[0]
	if keyType != keyTypeDirect && keyType != keyTypePwd {
		return nil, errInvalidPublicKey
	}
	keyBytes := pubKeyBytes[1:]
	var spec *kdfSpec
	if keyType == keyTypePwd {
		specBytes := keyBytes[keyLength:]
		var err error
		if spec, err = parseKdfSpec(specBytes); err != nil {
			return nil, err
		}
		keyBytes = keyBytes[:keyLength]
	}
	eccPubKey, err := ecc.GetPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	publicKey := &PublicKey{
		keyType:   keyType,
		publicKey: eccPubKey,
		spec:      spec,
	}
	return publicKey, nil
}

func (publicKey *PublicKey) isPwdBased() bool {
	return publicKey.keyType%2 == 1
}

func (publicKey *PublicKey) keyBytesWithType() []byte {
	return append([]byte{publicKey.keyType}, publicKey.publicKey.Bytes()...)
}

// Bytes returns the public key as bytes.
func (publicKey *PublicKey) Bytes() []byte {
	if publicKey.isPwdBased() {
		return append(publicKey.keyBytesWithType(), publicKey.spec.bytes()...)
	} else {
		return publicKey.keyBytesWithType()
	}
}
