// Package noble implements a simple wrapper which makes working with argon2
// as simple as possible.
package noble

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

// Argon is the main type for this module. Creating a variable of this type (typically with
// the New function) gives access to the two methods GeneratePasswordKey and
type Argon struct {
	Time              uint32 // the amount of computation realized and therefore the execution time, given in number of iterations
	Memory            uint32 // the memory usage, given in kibibytes (1024 bytes).
	Threads           uint8  // the number of parallel threads.
	KeyLen            uint32 // the key length; for AES-256, use 32.
	MinPasswordLength uint32 // specifies a minimum length for the supplied password.
	Reader            Reader
}

// Reader is an interface used for testing purposes. In order to satisfy
// this interface, a type must implement this function.
type Reader interface {
	GenerateBytes(length int) ([]byte, error)
}

// RandomSourceReader is an empty type we use so we can swap in a test
// reader, to simulate the situation where we can't generate a salt
// using crypto/rand.
type RandomSourceReader struct{}

// GenerateBytes returns a salt for our hash.
func (r *RandomSourceReader) GenerateBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, _ = rand.Read(bytes)
	return bytes, nil
}

// New returns an instance of the Noble type with sensible defaults.
func New() Argon {
	return Argon{
		Time:              1,
		Memory:            60 * 1024,
		Threads:           4,
		KeyLen:            32,
		MinPasswordLength: 6,
		Reader:            &RandomSourceReader{},
	}
}

// GeneratePasswordKey takes a supplied plain text password and creates a key
// from it. The ID key is of type Argon2id, which is the current recommended
// version by OWASP.
func (a *Argon) GeneratePasswordKey(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("empty password not supported")
	}

	// Generate a salt.
	salt, err := a.Reader.GenerateBytes(16)
	if err != nil {
		return "", err
	}

	// Create the ID Key.
	hash := argon2.IDKey([]byte(password), salt, a.Time, a.Memory, a.Threads, a.KeyLen)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Build a string which includes the hash and necessary configuration of the key: the
	// amount of memory used, the time used, the number of threads, the salt, and the hash
	// of the password.
	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	full := fmt.Sprintf(format, argon2.Version, a.Memory, a.Time, a.Threads, b64Salt, b64Hash)
	return full, nil
}

// ComparePasswordAndKey compares a plain text password with the supplied key, and
// returns true if the hash in the key matches the password.
func (a *Argon) ComparePasswordAndKey(password, hash string) (bool, error) {

	parts := strings.Split(hash, "$")

	// Sanity check.
	if len(parts) != 6 {
		return false, errors.New("incorrectly formatted hash")
	}

	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &a.Memory, &a.Time, &a.Threads)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	a.KeyLen = uint32(len(decodedHash))

	comparisonHash := argon2.IDKey([]byte(password), salt, a.Time, a.Memory, a.Threads, a.KeyLen)

	return subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1, nil
}
