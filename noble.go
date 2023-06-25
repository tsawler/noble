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

type Argon struct {
	Time              uint32
	Memory            uint32
	Threads           uint8
	KeyLen            uint32
	MinPasswordLength uint32
}

// New returns an instance of the Noble type with sensible defaults.
func New() Argon {
	return Argon{
		Time:              1,
		Memory:            60 * 1024,
		Threads:           4,
		KeyLen:            32,
		MinPasswordLength: 6,
	}
}

func (a *Argon) GeneratePasswordKey(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("empty password not supported")
	}

	// Generate a salt.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Create the ID Key.
	hash := argon2.IDKey([]byte(password), salt, a.Time, a.Memory, a.Threads, a.KeyLen)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Build a string which includes the hash and necessary config informatioa.
	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	full := fmt.Sprintf(format, argon2.Version, a.Memory, a.Time, a.Threads, b64Salt, b64Hash)
	return full, nil
}

// ComparePasswordAndHash compares a plain text password with the supplied hash, and
// returns true if the hash matches the password.
func (a *Argon) ComparePasswordAndHash(password, hash string) (bool, error) {

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
