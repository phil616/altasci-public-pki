package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/auth"
	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/store"
)

func TestPostgresAuthCheckDoesNotConsumeCode(t *testing.T) {
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
	secret := bytes.Repeat([]byte{51}, 20)
	for name, value := range map[string]string{
		"DATABASE_URL": databaseURL, "PKI_LISTEN_ADDRESS": "127.0.0.1:8080", "PKI_DEVELOPMENT_INSECURE": "false",
		"PUBLIC_BASE_URL": "https://pki.example.test", "CONSOLE_BASE_URL": "https://console.example.test",
		"ROOT_USER_EMAIL": "check-root@example.test", "ROOT_USER_PASSWORD": strings.Repeat("8a", 16),
		"ROOT_USER_TOTP_SECRET":    strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)),
		"PKI_MASTER_KEY_ACTIVE_ID": "v1", "PKI_MASTER_KEYS": `{"v1":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `"}`,
		"TRUSTED_PROXY_CIDRS": "127.0.0.1/32", "TSA_MAX_CLOCK_UNCERTAINTY": "5s",
	} {
		t.Setenv(name, value)
	}
	cfg, err := consoleconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewService(data, cfg)
	if err != nil {
		t.Fatal(err)
	}
	root, err := service.BootstrapRoot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET root_totp_last_step=0,failed_login_count=0,
        locked_until=NULL,status='active' WHERE id=$1`, root.ID); err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	code := fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1_000_000)
	before, err := data.RootUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check := func(expected string) {
		t.Helper()
		var output bytes.Buffer
		if err := runAuthCheck(ctx, []string{"--totp-stdin"}, strings.NewReader(code+"\n"), &output); err != nil {
			t.Fatal(err)
		}
		var report auth.RootCheck
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.TOTPCodeStatus != expected || !report.PasswordMatches || !report.TOTPSecretMatches {
			t.Fatal("diagnostic disagrees with actual credentials")
		}
		for _, value := range []string{cfg.RootUserPassword, before.PasswordHash, os.Getenv("ROOT_USER_TOTP_SECRET"), `"` + code + `"`} {
			if strings.Contains(output.String(), value) {
				t.Fatal("diagnostic disclosed a credential")
			}
		}
	}
	check("valid")
	check("valid")
	after, err := data.RootUser(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only CLI changed account or replay state")
	}
	if _, err := service.Login(ctx, auth.LoginInput{Login: cfg.RootUserEmail, Password: cfg.RootUserPassword, TOTP: code}); err != nil {
		t.Fatalf("a code checked by the CLI could not subsequently log in: %v", err)
	}
	check("replayed")
}
