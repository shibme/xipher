package argon2

import (
	"errors"
)

const (
	keyLength        uint32 = 32
	argon2SaltLength uint8  = 16
	argon2Iterations uint32 = 12
	argon2Memory     uint32 = 16
	argon2Threads    uint8  = 1
)

var (
	errGeneratingSalt      = errors.New("error generating salt")
	errIncorrectSaltLength = errors.New("incorrect salt length. requires a salt length of " + string(argon2SaltLength) + " bytes")
)
