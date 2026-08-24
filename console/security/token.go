package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewToken returns a 256-bit URL-safe bearer value and the digest stored in
// PostgreSQL. The plaintext token is never persisted.
func NewToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	return token, digest[:], nil
}

func TokenDigest(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}
