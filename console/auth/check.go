package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

// RootCheck contains only diagnostic state, never credentials, hashes or codes.
type RootCheck struct {
	ServerTimeUTC              time.Time  `json:"server_time_utc"`
	DatabaseTimeUTC            time.Time  `json:"database_time_utc"`
	DatabaseClockOffsetSeconds float64    `json:"database_clock_offset_seconds"`
	RootFound                  bool       `json:"root_found"`
	EmailMatches               bool       `json:"configured_email_matches"`
	PasswordMatches            bool       `json:"configured_password_matches"`
	PasswordHashValid          bool       `json:"password_hash_valid"`
	TOTPStateInitialized       bool       `json:"totp_state_initialized"`
	TOTPSecretMatches          bool       `json:"configured_totp_secret_matches"`
	AccountStatus              string     `json:"account_status"`
	FailedLoginCount           int        `json:"failed_login_count"`
	LockedUntil                *time.Time `json:"locked_until"`
	LockActive                 bool       `json:"lock_active"`
	TOTPAlgorithm              string     `json:"totp_algorithm"`
	TOTPDigits                 int        `json:"totp_digits"`
	TOTPPeriodSeconds          int64      `json:"totp_period_seconds"`
	CurrentTOTPStep            int64      `json:"current_totp_step"`
	LastAcceptedTOTPStep       int64      `json:"last_accepted_totp_step"`
	TOTPStateAhead             bool       `json:"totp_state_ahead_of_clock"`
	TOTPCodeStatus             string     `json:"totp_code_status"`
	Issues                     []string   `json:"issues"`
}

// CheckRoot reads the same credentials and verifier as Login without
// bootstrapping, creating sessions, consuming a code or changing lock counters.
// It is for the local operator CLI, never an unauthenticated HTTP endpoint.
func (s *Service) CheckRoot(ctx context.Context, code string) (RootCheck, error) {
	now := s.now().UTC()
	r := RootCheck{ServerTimeUTC: now, TOTPAlgorithm: "SHA256", TOTPDigits: 6,
		TOTPPeriodSeconds: security.TOTPPeriod, CurrentTOTPStep: now.Unix() / security.TOTPPeriod,
		TOTPCodeStatus: "not_supplied", Issues: []string{}}
	if err := s.store.Pool().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&r.DatabaseTimeUTC); err != nil {
		return r, err
	}
	r.DatabaseTimeUTC = r.DatabaseTimeUTC.UTC()
	r.DatabaseClockOffsetSeconds = r.DatabaseTimeUTC.Sub(now).Seconds()
	user, err := s.store.RootUser(ctx)
	if errors.Is(err, store.ErrNotFound) {
		r.Issues = append(r.Issues, "root_not_found")
		return r, nil
	}
	if err != nil {
		return r, err
	}
	r.RootFound = true
	r.EmailMatches = user.Email != nil && strings.EqualFold(*user.Email, s.config.RootUserEmail)
	r.PasswordMatches, err = security.VerifyPassword(s.config.RootUserPassword, user.PasswordHash)
	r.PasswordHashValid = err == nil
	r.TOTPStateInitialized = len(user.RootTOTPSecretHash) > 0
	digest := sha256.Sum256(s.config.RootUserTOTPSecret)
	r.TOTPSecretMatches = subtle.ConstantTimeCompare(digest[:], user.RootTOTPSecretHash) == 1
	r.AccountStatus, r.LockedUntil, r.FailedLoginCount = user.Status, user.LockedUntil, user.FailedLoginCount
	r.LockActive = user.LockedUntil != nil && user.LockedUntil.After(now)
	r.LastAcceptedTOTPStep = user.TOTPLastStep
	r.TOTPStateAhead = user.TOTPLastStep > r.CurrentTOTPStep+1
	for _, check := range []struct {
		ok    bool
		issue string
	}{
		{r.EmailMatches, "root_email_mismatch"}, {r.PasswordHashValid, "invalid_password_hash"},
		{r.PasswordMatches, "root_password_mismatch"}, {r.TOTPStateInitialized, "totp_state_not_initialized"},
		{!r.TOTPStateInitialized || r.TOTPSecretMatches, "totp_secret_mismatch"},
		{user.Status != "disabled", "account_disabled"}, {!r.LockActive, "account_locked"},
		{!r.TOTPStateAhead, "totp_state_ahead_of_clock"},
	} {
		if !check.ok {
			r.Issues = append(r.Issues, check.issue)
		}
	}
	if code != "" {
		_, err := security.VerifyTOTP(s.config.RootUserTOTPSecret, code, now, user.TOTPLastStep)
		switch {
		case err == nil:
			r.TOTPCodeStatus = "valid"
		case errors.Is(err, security.ErrTOTPClockBehind):
			r.TOTPCodeStatus = "clock_behind"
		case errors.Is(err, security.ErrTOTPReplayed):
			r.TOTPCodeStatus = "replayed"
		default:
			r.TOTPCodeStatus = "invalid"
		}
		if err != nil {
			r.Issues = append(r.Issues, "totp_code_"+r.TOTPCodeStatus)
		}
	}
	return r, nil
}
