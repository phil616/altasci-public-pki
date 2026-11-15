package config

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	setValidEnvironment(t)

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RootUserEmail != "root@example.com" || c.PublicHostname != "pki.example.com" ||
		c.DatabaseURL != "postgresql://pki_console:secret@db.example.com:5432/pki?sslmode=verify-full" ||
		c.TSAMaxClockUncertainty != 5*time.Second {
		t.Fatalf("unexpected config: %#v", c)
	}
}

func TestDefaultListenerAndNoCloudConfiguration(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("PKI_LISTEN_ADDRESS", "")
	c, err := Load()
	if err != nil || c.ListenAddress != "127.0.0.1:8080" {
		t.Fatalf("standalone defaults failed: address=%s err=%v", c.ListenAddress, err)
	}
}

func TestLoadRejectsBaseURLPath(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("PUBLIC_BASE_URL", "https://pki.example.com/prefix")
	if _, err := Load(); err == nil {
		t.Fatal("base URL with unsupported path accepted")
	}
}

func TestLoadRejectsInvalidTSAClockUncertainty(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("TSA_MAX_CLOCK_UNCERTAINTY", "0s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "between 1ms and 1m") {
		t.Fatalf("expected TSA clock uncertainty validation error, got %v", err)
	}
}

func TestLoadRejectsInsecureExternalDatabase(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("DATABASE_URL", "postgresql://pki_console:secret@db.example.com:5432/pki?sslmode=disable")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "cannot disable TLS") {
		t.Fatalf("expected external database TLS validation error, got %v", err)
	}
}

func TestLoadAllowsInsecureLoopbackDatabase(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("DATABASE_URL", "postgresql://pki_console:secret@127.0.0.1:5432/pki?sslmode=disable")

	if _, err := Load(); err != nil {
		t.Fatalf("expected explicit loopback database to allow disabled TLS, got %v", err)
	}
}

func TestLoadRejectsHostnameWithDisabledDatabaseTLS(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("DATABASE_URL", "postgresql://pki_console:secret@localhost:5432/pki?sslmode=disable")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "explicit loopback IP") {
		t.Fatalf("expected hostname database TLS validation error, got %v", err)
	}
}

func TestLoadRejectsNonLoopbackProductionListener(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("PKI_LISTEN_ADDRESS", "0.0.0.0:8080")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "explicit loopback") {
		t.Fatalf("expected loopback listener validation error, got %v", err)
	}
}

func TestRejectsShortRootPassword(t *testing.T) {
	c := Config{RootUserPassword: "short"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "missing required") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestRootLoginConfigurationLimits(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"ROOT_USER_PASSWORD", strings.Repeat("p", 1025)},
		{"ROOT_USER_EMAIL", "Root <root@example.test>"},
		{"ROOT_USER_EMAIL", strings.Repeat("a", 250) + "@example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv(tc.name, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("accepted a root credential that login cannot use")
			}
		})
	}
}

func TestCanonicalOriginDefaultPort(t *testing.T) {
	for _, raw := range []string{"https://CONSOLE.example.test:443/", "http://CONSOLE.example.test:80/"} {
		u, err := parseHTTPSURL("CONSOLE_BASE_URL", raw, true)
		if err != nil || u.Host != "console.example.test" {
			t.Fatalf("default port would fail browser Origin check: %v %v", u, err)
		}
	}
}

func TestRejectsKnownExampleSecrets(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"ROOT_USER_PASSWORD", "replace-with-at-least-32-random-characters"},
		{"ROOT_USER_TOTP_SECRET", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(make([]byte, 20))},
		{"PKI_MASTER_KEYS", `{"v1":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv(tc.name, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("known example secret accepted")
			}
		})
	}
}

func TestRemoteDatabaseRequiresVerifiedTLS(t *testing.T) {
	for _, mode := range []string{"", "allow", "prefer", "require", "verify-ca"} {
		t.Run(mode, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv("DATABASE_URL", "postgresql://pki:secret@db.example.test/pki?sslmode="+mode)
			if _, err := Load(); err == nil {
				t.Fatal("unverified remote TLS accepted")
			}
		})
	}
}

func TestRejectsEquivalentPublicAndConsoleHosts(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("PUBLIC_BASE_URL", "https://PKI.EXAMPLE.COM.")
	t.Setenv("CONSOLE_BASE_URL", "https://pki.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("equivalent hostnames bypassed surface separation")
	}
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("PKI_LISTEN_ADDRESS", "127.0.0.1:8080")
	t.Setenv("DATABASE_URL", "postgresql://pki_console:secret@db.example.com:5432/pki?sslmode=verify-full")
	t.Setenv("PUBLIC_BASE_URL", "https://pki.example.com")
	t.Setenv("CONSOLE_BASE_URL", "https://pki-console.example.com")
	t.Setenv("ROOT_USER_EMAIL", "ROOT@example.com")
	t.Setenv("ROOT_USER_PASSWORD", strings.Repeat("p", 32))
	t.Setenv("ROOT_USER_TOTP_SECRET", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{1}, 20)))
	t.Setenv("PKI_MASTER_KEY_ACTIVE_ID", "v1")
	t.Setenv("PKI_MASTER_KEYS", `{"v1":"`+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))+`"}`)
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
}
