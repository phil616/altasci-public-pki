package config

import (
	"encoding/base32"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://pki_console:secret@db.example.com:5432/pki?sslmode=verify-full")
	t.Setenv("PUBLIC_BASE_URL", "https://pki.example.com")
	t.Setenv("CONSOLE_BASE_URL", "https://pki-console.example.com")
	t.Setenv("ROOT_USER_EMAIL", "ROOT@example.com")
	t.Setenv("ROOT_USER_PASSWORD", strings.Repeat("p", 32))
	t.Setenv("ROOT_USER_TOTP_SECRET", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(make([]byte, 20)))
	t.Setenv("CF_ACCESS_TEAM_DOMAIN", "https://example.cloudflareaccess.com")
	t.Setenv("CF_ACCESS_AUD", "audience")
	t.Setenv("PKI_MASTER_KEY_ACTIVE_ID", "v1")
	t.Setenv("PKI_MASTER_KEYS", `{"v1":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"}`)

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RootUserEmail != "root@example.com" || c.PublicHostname != "pki.example.com" ||
		c.DatabaseURL != "postgresql://pki_console:secret@db.example.com:5432/pki?sslmode=verify-full" {
		t.Fatalf("unexpected config: %#v", c)
	}
}

func TestLoadRejectsInsecureExternalDatabase(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://pki_console:secret@db.example.com:5432/pki?sslmode=disable")
	t.Setenv("PUBLIC_BASE_URL", "https://pki.example.com")
	t.Setenv("CONSOLE_BASE_URL", "https://pki-console.example.com")
	t.Setenv("ROOT_USER_EMAIL", "root@example.com")
	t.Setenv("ROOT_USER_PASSWORD", strings.Repeat("p", 32))
	t.Setenv("ROOT_USER_TOTP_SECRET", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(make([]byte, 20)))
	t.Setenv("CF_ACCESS_TEAM_DOMAIN", "https://example.cloudflareaccess.com")
	t.Setenv("CF_ACCESS_AUD", "audience")
	t.Setenv("PKI_MASTER_KEY_ACTIVE_ID", "v1")
	t.Setenv("PKI_MASTER_KEYS", `{"v1":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"}`)

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "cannot disable TLS") {
		t.Fatalf("expected external database TLS validation error, got %v", err)
	}
}

func TestRejectsShortRootPassword(t *testing.T) {
	c := Config{RootUserPassword: "short"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "missing required") {
		t.Fatalf("expected validation error, got %v", err)
	}
}
