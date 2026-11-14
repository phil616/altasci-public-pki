// Package auth implements local password/TOTP credentials and
// server-side session authentication.
package auth

import (
	"context"
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
		if verifyErr == nil && matches && emailMatches && existing.Status == "active" {
			return existing, nil
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	hash, err := security.HashPassword(s.config.RootUserPassword)
	if err != nil {
		return store.User{}, err
	}
	return s.store.UpsertRoot(ctx, s.config.RootUserEmail, hash)
}

func (s *Service) Login(ctx context.Context, input LoginInput) (LoginResult, error) {
	if len(input.Login) > 254 || len(input.Password) > 1024 || len(input.TOTP) > 6 {
		return LoginResult{}, invalidCredentials("input_limits", nil)
	}
	now := s.now()
	user, err := s.store.UserByLogin(ctx, strings.TrimSpace(input.Login))
	if err != nil {
		_, _ = security.VerifyPassword(input.Password, s.dummy)
		return LoginResult{}, invalidCredentials("user_lookup", err)
	}
	if user.Status == "disabled" || (user.LockedUntil != nil && user.LockedUntil.After(now)) {
		return LoginResult{}, invalidCredentials("account_state", nil)
	}
	passwordOK, verifyErr := security.VerifyPassword(input.Password, user.PasswordHash)
	if verifyErr != nil || !passwordOK {
		return LoginResult{}, invalidCredentials("password", errors.Join(verifyErr, s.store.RecordLoginFailure(ctx, user.ID, now)))
	}

	var totpStep int64
	if user.Role == "super_admin" {
		totpStep, err = security.VerifyTOTP(s.config.RootUserTOTPSecret, input.TOTP, now, user.TOTPLastStep)
		if err != nil {
			return LoginResult{}, invalidCredentials("totp", errors.Join(err, s.store.RecordLoginFailure(ctx, user.ID, now)))
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
		return LoginResult{}, fmt.Errorf("create session: %w", err)
	}
	return LoginResult{User: user, SessionID: sessionID, Token: token, CSRFToken: csrfToken,
		ExpiresAt: now.Add(absolute)}, nil
}

func invalidCredentials(stage string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w at %s: %v", ErrInvalidCredentials, stage, cause)
	}
	return fmt.Errorf("%w at %s", ErrInvalidCredentials, stage)
}

func (s *Service) Authenticate(ctx context.Context, token, csrfToken, method string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrInvalidCredentials
	}
	now := s.now()
	session, err := s.store.SessionByToken(ctx, security.TokenDigest(token), now)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		got := security.TokenDigest(csrfToken)
		if len(got) != len(session.CSRFHash) || subtle.ConstantTimeCompare(got, session.CSRFHash) != 1 {
			return Principal{}, errors.New("invalid CSRF token")
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
