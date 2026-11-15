package auth

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

func TestPostgresPasswordAuthentication(t *testing.T) {
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
	cfg := consoleconfig.Config{RootUserEmail: "root-login@example.test", RootUserPassword: "root-password-with-special-chars-$! 'and spaces",
		SessionIdle: time.Minute, SessionMax: time.Hour, RootSessionIdle: time.Minute, RootSessionMax: time.Hour}
	service, err := NewService(data, cfg)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.BootstrapRoot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='active',locked_until=NULL,failed_login_count=0 WHERE id=$1`, root.ID); err != nil {
		t.Fatal(err)
	}
	first, err := service.Login(ctx, LoginInput{Login: strings.ToUpper(cfg.RootUserEmail), Password: cfg.RootUserPassword})
	if err != nil {
		t.Fatalf("root password login failed: %v", err)
	}
	second, err := service.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword})
	if err != nil || first.Token == second.Token {
		t.Fatal("repeated login must issue an independent session")
	}
	for _, session := range []LoginResult{first, second} {
		if _, err := service.Authenticate(ctx, session.Token, session.CSRFToken, "POST"); err != nil {
			t.Fatal(err)
		}
	}
	unchanged, err := service.BootstrapRoot(ctx)
	if err != nil || unchanged.PasswordHash != root.PasswordHash {
		t.Fatal("restart rehashed an unchanged password")
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='locked',failed_login_count=5,locked_until=now()+interval '15 minutes' WHERE id=$1`, root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword}); err == nil {
		t.Fatal("lock was bypassed")
	}
	cfg.RootUserPassword = "rotated-root-password-at-least-32-characters"
	service, err = NewService(data, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.BootstrapRoot(ctx)
	if err != nil || rotated.LockedUntil != nil || rotated.FailedLoginCount != 0 {
		t.Fatal("credential recovery retained the previous lock")
	}
	if _, err := service.Authenticate(ctx, first.Token, "", "GET"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("password rotation retained old sessions")
	}
	if err := data.VerifyRootPasswordSnapshot(ctx, root.ID, root.PasswordHash); err == nil {
		t.Fatal("old password snapshot authorized export")
	}
	if err := data.VerifyRootPasswordSnapshot(ctx, rotated.ID, rotated.PasswordHash); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='locked',failed_login_count=5,locked_until=now()-interval '1 second' WHERE id=$1`, root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(ctx, LoginInput{Login: cfg.RootUserEmail, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("wrong password accepted")
	}
	after, err := data.RootUser(ctx)
	if err != nil || after.FailedLoginCount != 1 || after.LockedUntil != nil || after.Status != "active" {
		t.Fatal("expired lock immediately relocked the account")
	}

	hash, err := security.HashPassword("ordinary-password-with-enough-characters")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"user", "operator"} {
		name, _, _ := security.NewToken()
		email := "password-" + name + "@example.test"
		user, err := data.CreateUser(ctx, "password-"+name, &email, role, hash)
		if err != nil {
			t.Fatal(err)
		}
		for _, login := range []string{user.Username, strings.ToUpper(email)} {
			result, err := service.Login(ctx, LoginInput{Login: login, Password: "ordinary-password-with-enough-characters"})
			if err != nil || result.User.ID != user.ID {
				t.Fatalf("%s password login failed: %v", role, err)
			}
		}
		if _, err := data.CreateUser(ctx, email, nil, "user", hash); err == nil {
			t.Fatal("username reused another account's email")
		}
		alias := user.Username
		if _, err := data.CreateUser(ctx, "conflict-"+name, &alias, "user", hash); err == nil {
			t.Fatal("email reused another account's username")
		}
	}
}
