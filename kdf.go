package xipher

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

const (
	specParamsLenth = 3
	saltLength      = 16
	specLength      = specParamsLenth + saltLength
)

type kdfSpec struct {
	iterations uint8
	memory     uint8
	threads    uint8
	salt       []byte
}

func newSpec() (*kdfSpec, error) {
	return new(kdfSpec).new()
}

func (s *kdfSpec) new() (*kdfSpec, error) {
	s.iterations = argon2Iterations
	s.memory = argon2Memory
	s.threads = argon2Threads
	s.salt = make([]byte, saltLength)
	if _, err := rand.Read(s.salt); err != nil {
		return nil, errGeneratingSalt
	}
	return s, nil
}

func (s *kdfSpec) setIterations(iterations uint8) *kdfSpec {
	if iterations > 0 {
		s.iterations = iterations
	}
	return s
}

// setMemory sets the amount of memory to be used in MB.
func (s *kdfSpec) setMemory(memory uint8) *kdfSpec {
	if memory > 0 {
		s.memory = memory
	}
	return s
}

func (s *kdfSpec) setThreads(threads uint8) *kdfSpec {
	if threads > 0 {
		s.threads = threads
	}
	return s
}

func (s *kdfSpec) getSalt() []byte {
	return s.salt
}

func (s *kdfSpec) getIterations() uint32 {
	return uint32(s.iterations)
}

func (s *kdfSpec) getMemory() uint32 {
	return uint32(s.memory) * 1024
}

func (s *kdfSpec) getThreads() uint32 {
	return uint32(s.threads)
}

func (s *kdfSpec) getCipherKey(pwd []byte) []byte {
	return argon2.IDKey(pwd, s.getSalt(), s.getIterations(), s.getMemory(), uint8(s.getThreads()), cipherKeyLength)
}

func (s *kdfSpec) Bytes() []byte {
	return append([]byte{s.iterations, s.memory, s.threads}, s.salt...)
}

func parseKdfSpec(bytes []byte) (*kdfSpec, error) {
	if bytes == nil || len(bytes) != specLength {
		return nil, errInvalidKDFSpec
	}
	if [specLength]byte(bytes) == [specLength]byte{} {
		return nil, nil
	}
	iterations := bytes[0]
	memory := bytes[1]
	threads := bytes[2]
	salt := bytes[specParamsLenth:]
	if iterations == 0 || memory == 0 || threads == 0 || salt == nil {
		return nil, errInvalidKDFSpec
	}
	return &kdfSpec{
		iterations: iterations,
		memory:     memory,
		threads:    threads,
		salt:       salt,
	}, nil
}
