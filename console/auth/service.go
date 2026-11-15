// Package auth implements local password/TOTP credentials and
// server-side session authentication.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

const CookieName = "__Host-pki_session"
const DevelopmentCookieName = "pki_session"

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrSecondFactorRequired = errors.New("second factor required")
var ErrInvalidCSRF = errors.New("invalid CSRF token")

type AccountLockedError struct{ Until time.Time }

func (e *AccountLockedError) Error() string { return "account is temporarily locked" }
func (e *AccountLockedError) Unwrap() error { return ErrInvalidCredentials }

type Service struct {
	store  *store.Store
	config consoleconfig.Config
	now    func() time.Time
	dummy  string
}

type LoginInput struct {
	Login     string
	Password  string
	TOTP      string
	IP        string
	UserAgent string
}

type LoginResult struct {
	User      store.User
	SessionID string
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

type Principal struct {
	User      store.User
	SessionID string
}

func NewService(s *store.Store, cfg consoleconfig.Config) (*Service, error) {
	if s == nil {
		return nil, errors.New("auth store is required")
	}
	dummy, err := security.HashPassword("pki-console-dummy-password-value")
	if err != nil {
		return nil, err
	}
	return &Service{store: s, config: cfg, now: time.Now, dummy: dummy}, nil
}

// BootstrapRoot creates the single root account or synchronizes changed
// environment credentials without rehashing an unchanged password on restart.
func (s *Service) BootstrapRoot(ctx context.Context) (store.User, error) {
	existing, err := s.store.RootUser(ctx)
	if err == nil {
		matches, verifyErr := security.VerifyPassword(s.config.RootUserPassword, existing.PasswordHash)
		emailMatches := existing.Email != nil && strings.EqualFold(*existing.Email, s.config.RootUserEmail)
		if verifyErr == nil && matches && emailMatches && existing.Status != "disabled" {
			return s.synchronizeRootTOTP(ctx, existing.ID)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	hash, err := security.HashPassword(s.config.RootUserPassword)
	if err != nil {
		return store.User{}, err
	}
	user, err := s.store.UpsertRoot(ctx, s.config.RootUserEmail, hash)
	if err != nil {
		return store.User{}, err
	}
	return s.synchronizeRootTOTP(ctx, user.ID)
}

func (s *Service) synchronizeRootTOTP(ctx context.Context, userID string) (store.User, error) {
	digest := sha256.Sum256(s.config.RootUserTOTPSecret)
	return s.store.SynchronizeRootTOTP(ctx, userID, digest[:])
}

func (s *Service) Login(ctx context.Context, input LoginInput) (LoginResult, error) {
	if len(input.Login) > 254 || len(input.Password) > 1024 || len(input.TOTP) > 6 {
		return LoginResult{}, invalidCredentials("input_limits", nil)
	}
	now := s.now()
	user, err := s.store.UserByLogin(ctx, strings.TrimSpace(input.Login))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return LoginResult{}, fmt.Errorf("look up login account: %w", err)
		}
		_, _ = security.VerifyPassword(input.Password, s.dummy)
		return LoginResult{}, invalidCredentials("user_lookup", err)
	}
	if user.Status == "disabled" {
		return LoginResult{}, invalidCredentials("account_state", nil)
	}
	locked := user.LockedUntil != nil && user.LockedUntil.After(now)
	passwordOK, verifyErr := security.VerifyPassword(input.Password, user.PasswordHash)
	if verifyErr != nil || !passwordOK {
		if locked {
			return LoginResult{}, invalidCredentials("account_state", nil)
		}
		return LoginResult{}, s.loginFailure(ctx, user.ID, now, "password", verifyErr)
	}
	// Reveal lock information only after verifying the password. Do not consume
	// a TOTP or extend the lock because a client retries during the lock period.
	if locked {
		return LoginResult{}, &AccountLockedError{Until: *user.LockedUntil}
	}

	var totpStep int64
	if user.Role == "super_admin" {
		digest := sha256.Sum256(s.config.RootUserTOTPSecret)
		if len(user.RootTOTPSecretHash) > 0 && subtle.ConstantTimeCompare(user.RootTOTPSecretHash, digest[:]) != 1 {
			return LoginResult{}, errors.New("root TOTP configuration changed; restart this process")
		}
		if input.TOTP == "" {
			return LoginResult{}, ErrSecondFactorRequired
		}
		totpStep, err = security.VerifyTOTP(s.config.RootUserTOTPSecret, input.TOTP, now, user.TOTPLastStep)
		if err != nil {
			if errors.Is(err, security.ErrTOTPClockBehind) {
				return LoginResult{}, err
			}
			return LoginResult{}, s.loginFailure(ctx, user.ID, now, "totp", err)
		}
	}
	token, tokenHash, err := security.NewToken()
	if err != nil {
		return LoginResult{}, err
	}
	csrfToken, csrfHash, err := security.NewToken()
	if err != nil {
		return LoginResult{}, err
	}
	idle, absolute := s.config.SessionIdle, s.config.SessionMax
	if user.Role == "super_admin" {
		idle, absolute = s.config.RootSessionIdle, s.config.RootSessionMax
	}
	sessionID, err := s.store.CreateAuthenticatedSession(ctx, user, totpStep, tokenHash, csrfHash, now.Add(idle), now.Add(absolute), now, input.IP, input.UserAgent)
	if err != nil {
		if errors.Is(err, store.ErrCredentialStateChanged) {
			return LoginResult{}, invalidCredentials("credential_state_changed", nil)
		}
		return LoginResult{}, fmt.Errorf("create session: %w", err)
	}
	return LoginResult{User: user, SessionID: sessionID, Token: token, CSRFToken: csrfToken,
		ExpiresAt: now.Add(absolute)}, nil
}

func (s *Service) loginFailure(ctx context.Context, userID string, now time.Time, stage string, cause error) error {
	if err := s.store.RecordLoginFailure(ctx, userID, now); err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return invalidCredentials(stage, cause)
}

type credentialError struct {
	stage string
	cause error
}

func (e *credentialError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%v at %s: %v", ErrInvalidCredentials, e.stage, e.cause)
	}
	return fmt.Sprintf("%v at %s", ErrInvalidCredentials, e.stage)
}

func (e *credentialError) Unwrap() []error {
	if e.cause != nil {
		return []error{ErrInvalidCredentials, e.cause}
	}
	return []error{ErrInvalidCredentials}
}

func invalidCredentials(stage string, cause error) error {
	return &credentialError{stage: stage, cause: cause}
}

// FailureStage is safe for logs: it contains no submitted credentials or keys.
func FailureStage(err error) string {
	var credential *credentialError
	var locked *AccountLockedError
	switch {
	case errors.As(err, &credential):
		return credential.stage
	case errors.As(err, &locked):
		return "account_locked"
	case errors.Is(err, security.ErrTOTPClockBehind):
		return "totp_clock_behind"
	case errors.Is(err, ErrSecondFactorRequired):
		return "second_factor_required"
	default:
		return "internal"
	}
}

func (s *Service) Authenticate(ctx context.Context, token, csrfToken, method string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrInvalidCredentials
	}
	now := s.now()
	session, err := s.store.SessionByToken(ctx, security.TokenDigest(token), now)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Principal{}, ErrInvalidCredentials
		}
		return Principal{}, fmt.Errorf("look up session: %w", err)
	}
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		got := security.TokenDigest(csrfToken)
		if len(got) != len(session.CSRFHash) || subtle.ConstantTimeCompare(got, session.CSRFHash) != 1 {
			return Principal{}, ErrInvalidCSRF
		}
	}
	principal := Principal{User: session.User, SessionID: session.ID}
	idle := s.config.SessionIdle
	if session.User.Role == "super_admin" {
		idle = s.config.RootSessionIdle
	}
	_ = s.store.TouchSession(ctx, session.ID, now.Add(idle), now)
	return principal, nil
}

func (s *Service) Logout(ctx context.Context, sessionID string) error {
	return s.store.RevokeSession(ctx, sessionID)
}
