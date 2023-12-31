package xipher

import (
	"crypto/rand"

	"gopkg.shib.me/xipher/internal/ecc"
	"gopkg.shib.me/xipher/internal/symmcipher"
)

type PrivateKey struct {
	password     *[]byte
	spec         *kdfSpec
	key          []byte
	symEncrypter *symmcipher.Cipher
	publicKey    *PublicKey
	specKeyMap   map[string][]byte
}

func (privateKey *PrivateKey) getCipherKey(specBytes []byte) (key []byte, err error) {
	key = privateKey.specKeyMap[string(specBytes)]
	if key == nil || len(key) == 0 {
		spec, err := parseKdfSpec(specBytes)
		if err != nil {
			return nil, err
		}
		key = spec.getCipherKey(*privateKey.password)
		privateKey.specKeyMap[string(specBytes)] = key
	}
	return key, nil
}

func NewPrivateKeyForPassword(password []byte) (*PrivateKey, error) {
	spec, err := new(kdfSpec).new()
	if err != nil {
		return nil, err
	}
	return newPrivateKeyForPwdAndSpec(password, spec)
}

func NewPrivateKeyForPasswordAndSpec(password []byte, iterations, memory, threads uint8) (*PrivateKey, error) {
	spec, err := new(kdfSpec).new()
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
	privateKey := pwdXipherMap[string(password)]
	if privateKey == nil {
		privateKey = &PrivateKey{
			password: &password,
			spec:     spec,
		}
		privateKey.key = spec.getCipherKey(*privateKey.password)
		pwdXipherMap[string(*privateKey.password)] = privateKey
		privateKey.specKeyMap = make(map[string][]byte)
		privateKey.specKeyMap[string(privateKey.spec.Bytes())] = privateKey.key
	}
	return privateKey, nil
}

func NewPrivateKey() (*PrivateKey, error) {
	key := make([]byte, cipherKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	privateKey := &PrivateKey{
		key: key,
	}
	keyXipherMap[string(key)] = privateKey
	return privateKey, nil
}

func ParsePrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != cipherKeyLength {
		return nil, errIncorrectKeyLength
	}
	privateKey := keyXipherMap[string(key)]
	if privateKey == nil {
		privateKey = &PrivateKey{
			key: key,
		}
		keyXipherMap[string(key)] = privateKey
	}
	return privateKey, nil
}

func (privateKey *PrivateKey) isPwdBased() bool {
	return privateKey.password != nil && privateKey.spec != nil
}

func (privateKey *PrivateKey) Bytes() ([]byte, error) {
	if privateKey.password != nil || privateKey.spec != nil {
		return nil, errPrivKeyUnavailableForPwd
	}
	return privateKey.key, nil
}

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
			publicKey: eccPubKey,
			spec:      privateKey.spec,
		}
	}
	return privateKey.publicKey, nil
}

type PublicKey struct {
	publicKey *ecc.PublicKey
	spec      *kdfSpec
}

func ParsePublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) != PublicKeyLength {
		return nil, errIncorrectKeyLength
	}
	eccPubKey, err := ecc.GetPublicKey(pubKeyBytes[:cipherKeyLength])
	if err != nil {
		return nil, err
	}
	publicKey := &PublicKey{
		publicKey: eccPubKey,
	}
	specBytes := pubKeyBytes[cipherKeyLength:]
	if [specLength]byte(specBytes) != [specLength]byte{} {
		publicKey.spec, err = parseKdfSpec(specBytes)
		if err != nil {
			return nil, err
		}
	}
	return publicKey, nil
}

func (publicKey *PublicKey) isPwdBased() bool {
	return publicKey.spec != nil
}

func (publicKey *PublicKey) Bytes() []byte {
	if publicKey.spec != nil {
		return append(publicKey.publicKey.Bytes(), publicKey.spec.Bytes()...)
	} else {
		return append(publicKey.publicKey.Bytes(), make([]byte, specLength)...)
	}
}
