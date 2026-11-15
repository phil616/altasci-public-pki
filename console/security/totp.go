package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// TOTPPeriod is the shared RFC 6238 time step in seconds.
const TOTPPeriod = int64(30)
const totpPeriod = TOTPPeriod

var ErrTOTPInvalid = errors.New("invalid TOTP code")
var ErrTOTPReplayed = errors.New("TOTP code has already been used")
var ErrTOTPClockBehind = errors.New("current TOTP code is valid but the stored replay counter is ahead of the server clock")

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
	matchedUsed := false
	for offset := int64(-1); offset <= 1; offset++ {
		candidate := counter + offset
		if hmac.Equal([]byte(code), []byte(totpCode(secret, candidate))) {
			if candidate <= lastAccepted {
				matchedUsed = true
				continue
			}
			return candidate, nil
		}
	}
	if matchedUsed {
		if lastAccepted > counter+1 {
			return 0, ErrTOTPClockBehind
		}
		return 0, ErrTOTPReplayed
	}
	return 0, ErrTOTPInvalid
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
