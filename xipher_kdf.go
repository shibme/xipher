package xipher

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

// kdfSpec represents a Key Derivation Function specification using Argon2.
// It contains all the parameters needed to derive a cryptographic key from a password,
// including the computational parameters and a random salt.
type kdfSpec struct {
	iterations uint8  // Number of iterations (time parameter)
	memory     uint8  // Memory size in MB (memory parameter)
	threads    uint8  // Number of threads (parallelism parameter)
	salt       []byte // Random salt (16 bytes)
}

// newSpec creates a new KDF specification with the given parameters and a random salt.
// The iterations, memory, and threads parameters control the computational cost of key derivation.
//
// Parameters:
//   - iterations: Number of iterations for Argon2 (must be > 0)
//   - memory: Memory size in MB for Argon2 (must be > 0)
//   - threads: Number of threads for parallel processing (must be > 0)
//
// Returns an error if any parameter is zero or if salt generation fails.
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

// getCipherKey derives a cryptographic key from a password using Argon2.
// It uses the KDF specification's parameters (iterations, memory, threads, salt)
// to derive a key of the required length for cryptographic operations.
//
// Parameters:
//   - pwd: The password to derive the key from
//
// Returns a derived key of secretKeyBaseLength bytes.
func (s *kdfSpec) getCipherKey(pwd []byte) []byte {
	return argon2.IDKey(pwd, s.salt, uint32(s.iterations), uint32(s.memory)*1024, uint8(uint32(s.threads)), secretKeyBaseLength)
}

// bytes serializes the KDF specification into a byte slice.
// The format is: [iterations][memory][threads][salt...]
// This serialized form is used when storing or transmitting the KDF parameters.
func (s *kdfSpec) bytes() []byte {
	return append([]byte{s.iterations, s.memory, s.threads}, s.salt...)
}

// parseKdfSpec parses a serialized KDF specification from bytes.
// It expects exactly kdfSpecLength bytes in the format: [iterations][memory][threads][salt...]
//
// Parameters:
//   - kdfBytes: Serialized KDF specification bytes
//
// Returns the parsed KDF specification or an error if the format is invalid.
// Returns nil if the input is all zeros (indicating no KDF spec).
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
