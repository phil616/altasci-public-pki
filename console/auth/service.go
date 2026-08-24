// Package auth implements local credentials, Cloudflare Access step-up, and
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
	access *security.AccessVerifier
	now    func() time.Time
	dummy  string
}

type LoginInput struct {
	Login             string
	Password          string
	TOTP              string
	AccessJWT         string
	AccessEmailHeader string
	IP                string
	UserAgent         string
}

type LoginResult struct {
	User      store.User
	SessionID string
	Token     string
	CSRFToken string
	ExpiresAt time.Time
	AccessSub string
}

type Principal struct {
	User      store.User
	SessionID string
	AccessSub string
}

func NewService(s *store.Store, cfg consoleconfig.Config, verifier *security.AccessVerifier) (*Service, error) {
	if s == nil || verifier == nil {
		return nil, errors.New("auth store and Access verifier are required")
	}
	dummy, err := security.HashPassword("pki-console-dummy-password-value")
	if err != nil {
		return nil, err
	}
	return &Service{store: s, config: cfg, access: verifier, now: time.Now, dummy: dummy}, nil
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
	now := s.now()
	user, err := s.store.UserByLogin(ctx, strings.TrimSpace(input.Login))
	if err != nil {
		_, _ = security.VerifyPassword(input.Password, s.dummy)
		return LoginResult{}, ErrInvalidCredentials
	}
	if user.Status == "disabled" || (user.LockedUntil != nil && user.LockedUntil.After(now)) {
		return LoginResult{}, ErrInvalidCredentials
	}
	passwordOK, verifyErr := security.VerifyPassword(input.Password, user.PasswordHash)
	if verifyErr != nil || !passwordOK {
		_ = s.store.RecordLoginFailure(ctx, user.ID, now)
		return LoginResult{}, ErrInvalidCredentials
	}

	var totpStep int64
	var accessSub string
	if user.Role == "super_admin" {
		identity, err := s.access.Verify(ctx, input.AccessJWT, input.AccessEmailHeader, s.config.RootUserEmail)
		if err != nil {
			_ = s.store.RecordLoginFailure(ctx, user.ID, now)
			return LoginResult{}, ErrInvalidCredentials
		}
		accessSub = identity.Subject
		totpStep, err = security.VerifyTOTP(s.config.RootUserTOTPSecret, input.TOTP, now, user.TOTPLastStep)
		if err != nil {
			_ = s.store.RecordLoginFailure(ctx, user.ID, now)
			return LoginResult{}, ErrInvalidCredentials
		}
	}
	if err := s.store.AcceptLogin(ctx, user, totpStep, now); err != nil {
		return LoginResult{}, ErrInvalidCredentials
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
	sessionID, err := s.store.CreateSession(ctx, user.ID, tokenHash, csrfHash, now.Add(idle), now.Add(absolute), input.IP, input.UserAgent)
	if err != nil {
		return LoginResult{}, fmt.Errorf("create session: %w", err)
	}
	return LoginResult{User: user, SessionID: sessionID, Token: token, CSRFToken: csrfToken,
		ExpiresAt: now.Add(absolute), AccessSub: accessSub}, nil
}

func (s *Service) Authenticate(ctx context.Context, token, csrfToken, method, accessJWT, accessEmail string) (Principal, error) {
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
	if session.User.Role == "super_admin" {
		identity, err := s.access.Verify(ctx, accessJWT, accessEmail, s.config.RootUserEmail)
		if err != nil {
			return Principal{}, errors.New("Cloudflare Access verification failed")
		}
		principal.AccessSub = identity.Subject
	}
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
