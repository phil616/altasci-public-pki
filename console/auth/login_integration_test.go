package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

func TestPostgresRootAuthenticationLifecycle(t *testing.T) {
	databaseURL := os.Getenv("PKI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PKI_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	data := store.New(pool)
	cfg := consoleconfig.Config{RootUserEmail: "root-login@example.test",
		RootUserPassword:   "root-password-with-special-chars-$! 'and spaces",
		RootUserTOTPSecret: bytes.Repeat([]byte{31}, 32),
		SessionIdle:        time.Minute, SessionMax: time.Hour,
		RootSessionIdle: time.Minute, RootSessionMax: time.Hour}
	newService := func(config consoleconfig.Config) *Service {
		t.Helper()
		s, err := NewService(data, config)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := newService(cfg)
	root, err := s.BootstrapRoot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// These tests use only the explicitly supplied disposable test database.
	if _, err := pool.Exec(ctx, `UPDATE users SET status='active',locked_until=NULL,
        failed_login_count=0,root_totp_last_step=0 WHERE id=$1`, root.ID); err != nil {
		t.Fatal(err)
	}
	t.Run("missing factor does not lock a correct password", func(t *testing.T) {
		for i := 0; i < 6; i++ {
			if _, err := s.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword}); !errors.Is(err, ErrSecondFactorRequired) {
				t.Fatalf("expected second-factor challenge: %v", err)
			}
		}
		user, err := data.RootUser(ctx)
		if err != nil || user.FailedLoginCount != 0 || user.LockedUntil != nil {
			t.Fatalf("missing factor locked a correct password: count=%d locked=%v err=%v", user.FailedLoginCount, user.LockedUntil != nil, err)
		}
	})
	t.Run("password rotation clears previous lock", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `UPDATE users SET status='locked',failed_login_count=5,
            locked_until=now()+interval '15 minutes' WHERE id=$1`, root.ID); err != nil {
			t.Fatal(err)
		}
		cfg.RootUserPassword = "rotated-root-password-at-least-32-characters"
		s = newService(cfg)
		if _, err := s.BootstrapRoot(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword,
			TOTP: loginTestCode(cfg.RootUserTOTPSecret, time.Now())}); err != nil {
			t.Fatalf("correct rotated credentials remain locked: %v", err)
		}
	})
	t.Run("expired lock starts a new failure window", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `UPDATE users SET status='locked',failed_login_count=5,
            locked_until=now()-interval '1 second' WHERE id=$1`, root.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password was not rejected: %v", err)
		}
		user, err := data.RootUser(ctx)
		if err != nil || user.FailedLoginCount != 1 || user.LockedUntil != nil || user.Status != "active" {
			t.Fatalf("first failure after lock expiry immediately relocked account: count=%d status=%s err=%v", user.FailedLoginCount, user.Status, err)
		}
	})
	t.Run("unchanged restart preserves replay state and lock", func(t *testing.T) {
		before, err := data.RootUser(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE users SET status='locked',failed_login_count=5,
            locked_until=now()+interval '15 minutes' WHERE id=$1`, root.ID); err != nil {
			t.Fatal(err)
		}
		restarted := newService(cfg)
		after, err := restarted.BootstrapRoot(ctx)
		if err != nil || after.PasswordHash != before.PasswordHash || after.TOTPLastStep != before.TOTPLastStep || after.Status != "locked" {
			t.Fatalf("unchanged restart changed credential/lock state: %v", err)
		}
		if _, err := restarted.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword,
			TOTP: loginTestCode(cfg.RootUserTOTPSecret, time.Now())}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("restart bypassed lock: %v", err)
		}
	})
	t.Run("TOTP rotation revokes sessions and stale verification", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `UPDATE users SET status='active',locked_until=NULL,
            failed_login_count=0,root_totp_last_step=0 WHERE id=$1`, root.ID); err != nil {
			t.Fatal(err)
		}
		oldService := s
		result, err := oldService.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword,
			TOTP: loginTestCode(cfg.RootUserTOTPSecret, time.Now())})
		if err != nil {
			t.Fatal(err)
		}
		stale, err := data.RootUser(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// A counter from a future clock/old secret must not block a new secret.
		if _, err := pool.Exec(ctx, `UPDATE users SET root_totp_last_step=$2 WHERE id=$1`, root.ID, time.Now().Unix()/30+100); err != nil {
			t.Fatal(err)
		}
		oldSecret := cfg.RootUserTOTPSecret
		cfg.RootUserTOTPSecret = bytes.Repeat([]byte{39}, 32)
		s = newService(cfg)
		fresh, err := s.BootstrapRoot(ctx)
		if err != nil || fresh.TOTPLastStep != 0 {
			t.Fatalf("secret rotation retained old replay counter: %v", err)
		}
		if _, err := s.Authenticate(ctx, result.Token, "", "GET"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("old root session survived secret rotation: %v", err)
		}
		if err := data.AcceptRootStepUp(ctx, stale.ID, stale.PasswordHash, stale.RootTOTPSecretHash, stale.TOTPLastStep+1); err == nil {
			t.Fatal("stale TOTP verification authorized step-up")
		}
		_, tokenHash, _ := security.NewToken()
		_, csrfHash, _ := security.NewToken()
		now := time.Now()
		if _, err := data.CreateAuthenticatedSession(ctx, stale, stale.TOTPLastStep+1,
			tokenHash, csrfHash, now.Add(time.Minute), now.Add(time.Hour), now, "", ""); !errors.Is(err, store.ErrCredentialStateChanged) {
			t.Fatalf("stale TOTP verification created session: %v", err)
		}
		if _, err := oldService.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword,
			TOTP: loginTestCode(oldSecret, time.Now())}); err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("old process did not reject its stale TOTP configuration: %v", err)
		}
		if _, err := s.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword,
			TOTP: loginTestCode(cfg.RootUserTOTPSecret, time.Now())}); err != nil {
			t.Fatalf("rotated TOTP could not log in: %v", err)
		}
	})
	t.Run("ordinary login and unique identity resolution", func(t *testing.T) {
		password := "ordinary-password-at-least-fifteen-bytes"
		hash, err := security.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		email := "ordinary-auth@example.test"
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE username IN ('ordinary-auth','legacy-auth')`)
		user, err := data.CreateUser(ctx, "ordinary-auth", &email, "user", hash)
		if err != nil {
			t.Fatal(err)
		}
		result, err := s.Login(ctx, LoginInput{Login: " ORDINARY-AUTH@example.test ", Password: password})
		if err != nil || result.User.ID != user.ID {
			t.Fatalf("ordinary email/password login failed: %v", err)
		}
		if _, err := s.Authenticate(ctx, result.Token, result.CSRFToken, "POST"); err != nil {
			t.Fatalf("ordinary session/CSRF rejected: %v", err)
		}
		if _, err := data.CreateUser(ctx, email, nil, "user", hash); err == nil {
			t.Fatal("username reused an existing email")
		}
		alias := user.Username
		if _, err := data.CreateUser(ctx, "legacy-auth", &alias, "user", hash); err == nil {
			t.Fatal("email reused an existing username")
		}
		// Simulate old ambiguous data, bypassing the application creation guard.
		if _, err := pool.Exec(ctx, `INSERT INTO users(username,email,role,password_hash)
            VALUES ('legacy-auth',$1,'user',$2)`, alias, hash); err != nil {
			t.Fatal(err)
		}
		if _, err := data.UserByLogin(ctx, alias); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("ambiguous login selected an arbitrary account: %v", err)
		}
	})
	t.Run("read-only checks identify future replay state", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `UPDATE users SET root_totp_last_step=$2,failed_login_count=0,
            locked_until=NULL,status='active' WHERE id=$1`, root.ID, time.Now().Unix()/30+100); err != nil {
			t.Fatal(err)
		}
		before, err := data.RootUser(ctx)
		if err != nil {
			t.Fatal(err)
		}
		code := loginTestCode(cfg.RootUserTOTPSecret, time.Now())
		if _, err := s.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword, TOTP: code}); !errors.Is(err, security.ErrTOTPClockBehind) {
			t.Fatalf("valid code rejected for future state was not identified: %v", err)
		}
		for i := 0; i < 2; i++ {
			report, err := s.CheckRoot(ctx, code)
			if err != nil || !report.PasswordMatches || !report.TOTPSecretMatches || !report.EmailMatches || !report.TOTPStateAhead || report.TOTPCodeStatus != "clock_behind" {
				t.Fatalf("root-state diagnostic missed the cause: %v", err)
			}
			encoded, _ := json.Marshal(report)
			if strings.Contains(string(encoded), cfg.RootUserPassword) || strings.Contains(string(encoded), before.PasswordHash) || strings.Contains(string(encoded), `"`+code+`"`) {
				t.Fatal("diagnostic output contains a credential")
			}
		}
		after, err := data.RootUser(ctx)
		if err != nil || before.TOTPLastStep != after.TOTPLastStep || after.FailedLoginCount != 0 || after.LockedUntil != nil || !before.UpdatedAt.Equal(after.UpdatedAt) {
			t.Fatal("diagnostics or a valid code blocked by clock state changed the account")
		}
		mismatched := cfg
		mismatched.RootUserPassword = "different-environment-password-at-least-32-characters"
		mismatched.RootUserTOTPSecret = bytes.Repeat([]byte{47}, 32)
		report, err := newService(mismatched).CheckRoot(ctx, "")
		if err != nil || report.PasswordMatches || report.TOTPSecretMatches {
			t.Fatal("a stale process environment was not detected")
		}
	})
}

func loginTestCode(secret []byte, now time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1_000_000)
}
