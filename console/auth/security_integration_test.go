package auth

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

func TestPostgresCredentialTransitions(t *testing.T) {
	url := os.Getenv("PKI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PKI_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	data := store.New(pool)
	name, _, _ := security.NewToken()
	user, err := data.CreateUser(ctx, "race-"+name, nil, "user", "old-verified-hash")
	if err != nil {
		t.Fatal(err)
	}
	newSession := func(snapshot store.User) (string, []byte, error) {
		_, digest, _ := security.NewToken()
		_, csrf, _ := security.NewToken()
		now := time.Now()
		id, err := data.CreateAuthenticatedSession(ctx, snapshot, digest, csrf, now.Add(time.Hour), now.Add(2*time.Hour), now, "127.0.0.1", "regression")
		return id, digest, err
	}
	for i := 0; i < 5; i++ {
		if err := data.RecordLoginFailure(ctx, user.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	locked, err := data.UserByID(ctx, user.ID)
	if err != nil || locked.Status != "locked" || locked.FailedLoginCount != 5 || locked.LockedUntil == nil {
		t.Fatalf("failed login lock did not engage: %#v %v", locked, err)
	}
	if _, _, err := newSession(user); err == nil {
		t.Fatal("locked account created session")
	}
	if err := data.SetUserStatus(ctx, user.ID, "active"); err != nil {
		t.Fatal(err)
	}
	if err := data.ResetUserPassword(ctx, user.ID, "new-verified-hash"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newSession(user); err == nil {
		t.Fatal("stale password verification created a session after reset")
	}
	user, err = data.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := newSession(user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SessionByToken(ctx, digest, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := data.SetUserStatus(ctx, user.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if err := data.RecordLoginFailure(ctx, user.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	disabled, err := data.UserByID(ctx, user.ID)
	if err != nil || disabled.Status != "disabled" {
		t.Fatalf("login failure reactivated disabled account: %s %v", disabled.Status, err)
	}
	if _, _, err := newSession(user); err == nil {
		t.Fatal("disabled account created a session")
	}
	if err := data.SetUserStatus(ctx, user.ID, "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := data.SessionByToken(ctx, digest, time.Now()); err == nil {
		t.Fatal("disable/re-enable revived an old session")
	}
	root, err := data.UpsertRoot(ctx, "root-security@example.test", "root-old-hash")
	if err != nil {
		t.Fatal(err)
	}
	_, rootDigest, err := newSession(root)
	if err != nil {
		t.Fatal(err)
	}
	root, err = data.UpsertRoot(ctx, "root-security@example.test", "root-new-hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.VerifyRootPasswordSnapshot(ctx, root.ID, "root-old-hash"); err == nil {
		t.Fatal("stale password verification authorized root key export")
	}
	if _, err := data.SessionByToken(ctx, rootDigest, time.Now()); err == nil {
		t.Fatal("root password rotation left an old session usable")
	}
	var successful atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := newSession(root); err == nil {
				successful.Add(1)
			}
		}()
	}
	wg.Wait()
	if successful.Load() != 2 {
		t.Fatalf("concurrent password sessions: %d sessions", successful.Load())
	}
}
