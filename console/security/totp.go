package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const totpPeriod = int64(30)

// VerifyTOTP validates a six-digit RFC 6238 HMAC-SHA-256 code. It returns the
// accepted counter so the caller can reject reuse transactionally.
func VerifyTOTP(secret []byte, code string, now time.Time, lastAccepted int64) (int64, error) {
	if len(secret) < 20 {
		return 0, errors.New("TOTP secret is too short")
	}
	if len(code) != 6 {
		return 0, errors.New("TOTP code must contain six digits")
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return 0, errors.New("TOTP code must contain only digits")
		}
	}
	counter := now.Unix() / totpPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		candidate := counter + offset
		if candidate <= lastAccepted {
			continue
		}
		if hmac.Equal([]byte(code), []byte(totpCode(secret, candidate))) {
			return candidate, nil
		}
	}
	return 0, errors.New("invalid or replayed TOTP code")
}

func totpCode(secret []byte, counter int64) string {
	if counter < 0 {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
