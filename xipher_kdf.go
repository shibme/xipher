package xipher

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

type kdfSpec struct {
	iterations uint8
	memory     uint8
	threads    uint8
	salt       []byte
}

func newSpec(iterations, memory, threads uint8) (*kdfSpec, error) {
	if iterations == 0 || memory == 0 || threads == 0 {
		return nil, errInvalidKDFSpec
	}
	salt := make([]byte, kdfSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, errGeneratingSalt
	}
	return &kdfSpec{
		iterations: iterations,
		memory:     memory,
		threads:    threads,
		salt:       salt,
	}, nil
}

func (s *kdfSpec) getCipherKey(pwd []byte) []byte {
	return argon2.IDKey(pwd, s.salt, uint32(s.iterations), uint32(s.memory)*1024, uint8(uint32(s.threads)), secretKeyBaseLength)
}

func (s *kdfSpec) bytes() []byte {
	return append([]byte{s.iterations, s.memory, s.threads}, s.salt...)
}

func parseKdfSpec(kdfBytes []byte) (*kdfSpec, error) {
	if kdfBytes == nil || len(kdfBytes) != kdfSpecLength {
		return nil, errInvalidKDFSpec
	}
	if [kdfSpecLength]byte(kdfBytes) == [kdfSpecLength]byte{} {
		return nil, nil
	}
	iterations := kdfBytes[0]
	memory := kdfBytes[1]
	threads := kdfBytes[2]
	salt := kdfBytes[kdfParamsLenth:]
	if iterations == 0 || memory == 0 || threads == 0 {
		return nil, errInvalidKDFSpec
	}
	spec := &kdfSpec{
		iterations: iterations,
		memory:     memory,
		threads:    threads,
		salt:       salt,
	}
	return spec, nil
}
