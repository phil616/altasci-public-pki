package security

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword(strings.Repeat("correct horse battery staple ", 2))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(strings.Repeat("correct horse battery staple ", 2), encoded)
	if err != nil || !ok {
		t.Fatalf("expected password match, ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword("wrong", encoded)
	if err != nil || ok {
		t.Fatalf("expected mismatch, ok=%v err=%v", ok, err)
	}
}

func TestTOTPReplayProtection(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	now := time.Unix(1_700_000_000, 0)
	code := totpCode(secret, now.Unix()/totpPeriod)
	step, err := VerifyTOTP(secret, code, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTOTP(secret, code, now, step); !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected a replay classification, got %v", err)
	}
	if _, err := VerifyTOTP(secret, code, now, step+100); !errors.Is(err, ErrTOTPClockBehind) {
		t.Fatalf("valid current code blocked by future state was not identified: %v", err)
	}
	if _, err := VerifyTOTP(secret, "abcdef", now, step+100); errors.Is(err, ErrTOTPClockBehind) {
		t.Fatal("invalid code disclosed a valid-code diagnostic")
	}
}

// RFC 6238 Appendix B SHA-256 vectors, reduced from eight to six digits.
func TestTOTPRFC6238SHA256(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	for _, tc := range []struct {
		unix int64
		code string
	}{
		{59, "119246"}, {1111111109, "084774"}, {1111111111, "062674"},
		{1234567890, "819424"}, {2000000000, "698825"}, {20000000000, "737706"},
	} {
		if _, err := VerifyTOTP(secret, tc.code, time.Unix(tc.unix, 0), 0); err != nil {
			t.Fatalf("SHA-256 vector at %d: %v", tc.unix, err)
		}
	}
	for _, code := range []string{"+12345", "-12345", "123 45", "１２３４５６"} {
		if _, err := VerifyTOTP(secret, code, time.Unix(59, 0), 0); err == nil {
			t.Fatalf("accepted malformed TOTP")
		}
	}
}

func TestKeyringAuthenticatedEncryption(t *testing.T) {
	ring := Keyring{ActiveID: "v1", Keys: map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)}}
	envelope, err := ring.Encrypt([]byte("private key"), []byte("ca:123"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ring.Decrypt(envelope, []byte("ca:123"))
	if err != nil || string(got) != "private key" {
		t.Fatalf("unexpected decryption result %q: %v", got, err)
	}
	if _, err := ring.Decrypt(envelope, []byte("ca:456")); err == nil {
		t.Fatal("expected AAD mismatch to fail")
	}
}
