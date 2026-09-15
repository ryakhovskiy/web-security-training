package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	memoryKiB        = 19 * 1024
	iterations       = 2
	parallelism      = 1
	MaxLength        = 128
	derivedKeyLength = 32
	argon2idVersion  = 19
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if nil != err {
		return "", err
	}
	params := argon2idHash{
		version:     argon2idVersion,
		memoryKiB:   memoryKiB,
		iterations:  iterations,
		parallelism: parallelism,
		salt:        salt,
		derivedKey:  nil,
	}

	derivedKey := argon2.IDKey([]byte(password), params.salt, params.iterations, params.memoryKiB, params.parallelism, derivedKeyLength)
	params.derivedKey = derivedKey
	return encodeArgon2idHash(params), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		params, ok := parseArgon2idHash(encodedHash)
		if !ok {
			return false
		}
		if params.version != argon2idVersion {
			return false
		}
		candidateKey := argon2.IDKey(
			[]byte(password),
			params.salt,
			params.iterations,
			params.memoryKiB,
			params.parallelism,
			uint32(len(params.derivedKey)),
		)
		return subtle.ConstantTimeCompare(candidateKey, params.derivedKey) == 1
	} else {
		expectedHash, ok := decodeLegacyHash(encodedHash)
		if !ok {
			return false
		}
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
}

func NeedsRehash(encodedHash string) bool {
	if !strings.HasPrefix(encodedHash, "$argon2id$") {
		return true
	}
	params, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return true
	}
	if params.version < argon2idVersion || len(params.derivedKey) < derivedKeyLength || params.memoryKiB < memoryKiB || params.iterations < iterations || params.parallelism < parallelism {
		return true
	}
	return false
}
