package store_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

func TestPostgresSchemaInitialization(t *testing.T) {
	databaseURL := os.Getenv("PKI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PKI_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	data := store.New(pool)
	if err := data.RequireCurrentSchema(ctx); err != nil {
		t.Fatal(err)
	}
	name, token, err := security.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, "schema-"+name, nil, "user", "test-hash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateSession(ctx, user.ID, token, token, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	// Concurrent initializers must serialize and leave existing identities and
	// sessions usable, rather than repeating pre-release authentication resets.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := store.Migrate(ctx, databaseURL); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if _, err := data.SessionByToken(ctx, token, time.Now()); err != nil {
		t.Fatalf("repeat initialization changed a session: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE pki_schema RENAME TO schema_test_saved_marker`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `ALTER TABLE schema_test_saved_marker RENAME TO pki_schema`); err != nil {
			t.Error(err)
		}
	}()
	if err := data.RequireCurrentSchema(ctx); err == nil {
		t.Fatal("startup accepted an unrecognized database")
	}
	if err := store.Migrate(ctx, databaseURL); err == nil || !strings.Contains(err.Error(), "nonempty") {
		t.Fatalf("expected rejection of a nonempty schema, got %v", err)
	}
	if _, err := data.SessionByToken(ctx, token, time.Now()); err != nil {
		t.Fatalf("rejected initialization changed existing data: %v", err)
	}
}
