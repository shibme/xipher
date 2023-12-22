package argon2

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

type keyDeriver struct {
	data       []byte
	length     uint32
	iterations uint32
	memory     uint32
	threads    uint8
	salt       []byte
}

// DeriveKey returns a builder with the given data and length.
func DeriveKey(data []byte) *keyDeriver {
	return &keyDeriver{
		data:       data,
		length:     keyLength,
		iterations: argon2Iterations,
		memory:     argon2Memory,
		threads:    argon2Threads,
	}
}

// Length sets the length of the key to be derived.
func (k *keyDeriver) Length(length uint32) *keyDeriver {
	if length > 0 {
		k.length = length
	}
	return k
}

// Iterations sets the number of iterations to be used.
func (k *keyDeriver) Iterations(iterations uint32) *keyDeriver {
	if iterations > 0 {
		k.iterations = iterations
	}
	return k
}

// Memory sets the amount of memory to be used in MB.
func (k *keyDeriver) Memory(memory uint32) *keyDeriver {
	if memory > 0 {
		k.memory = memory
	}
	return k
}

// Threads sets the number of threads to be used.
func (k *keyDeriver) Threads(threads uint8) *keyDeriver {
	if threads > 0 {
		k.threads = threads
	}
	return k
}

// Derive returns the derived key along with a random salt that was used.
func (k *keyDeriver) Derive() (key, salt []byte, err error) {
	if k.salt == nil {
		k.salt = make([]byte, argon2SaltLength)
		if _, err := rand.Read(k.salt); err != nil {
			return nil, nil, errGeneratingSalt
		}
	}
	return k.DeriveWithSalt(k.salt), k.salt, nil
}

// DeriveWithSalt returns the derived key with the given salt.
func (k *keyDeriver) DeriveWithSalt(salt []byte) (key []byte) {
	k.salt = salt
	if k.length == 0 {
		k.length = keyLength
	}
	return argon2.IDKey(k.data, k.salt, k.iterations, k.memory*1024, k.threads, k.length)
}
