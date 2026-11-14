// Package config loads and validates PKI-Console runtime configuration.
package config

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultListenAddress          = "127.0.0.1:8080"
	defaultSessionIdle            = 8 * time.Hour
	defaultSessionMax             = 24 * time.Hour
	defaultRootIdle               = 30 * time.Minute
	defaultRootMax                = 4 * time.Hour
	defaultTSAMaxClockUncertainty = 5 * time.Second
)

// Config contains all settings required by the API and worker processes.
// Secrets are intentionally kept out of String methods and structured logs.
type Config struct {
	ListenAddress          string
	DatabaseURL            string
	PublicBaseURL          *url.URL
	ConsoleBaseURL         *url.URL
	PublicHostname         string
	ConsoleHostname        string
	RootUserEmail          string
	RootUserPassword       string
	RootUserTOTPSecret     []byte
	MasterKeyActiveID      string
	MasterKeys             map[string][]byte
	SessionIdle            time.Duration
	SessionMax             time.Duration
	RootSessionIdle        time.Duration
	RootSessionMax         time.Duration
	TrustedProxyCIDRs      []string
	TSAMaxClockUncertainty time.Duration
	DevelopmentInsecure    bool
}

// Load reads configuration from environment variables and fails closed when a
// security-sensitive setting is absent or malformed.
func Load() (Config, error) {
	var err error
	c := Config{
		ListenAddress:          envDefault("PKI_LISTEN_ADDRESS", defaultListenAddress),
		DatabaseURL:            strings.TrimSpace(os.Getenv("DATABASE_URL")),
		RootUserEmail:          strings.ToLower(strings.TrimSpace(os.Getenv("ROOT_USER_EMAIL"))),
		RootUserPassword:       os.Getenv("ROOT_USER_PASSWORD"),
		MasterKeyActiveID:      strings.TrimSpace(os.Getenv("PKI_MASTER_KEY_ACTIVE_ID")),
		SessionIdle:            defaultSessionIdle,
		SessionMax:             defaultSessionMax,
		RootSessionIdle:        defaultRootIdle,
		RootSessionMax:         defaultRootMax,
		TrustedProxyCIDRs:      splitCSV(os.Getenv("TRUSTED_PROXY_CIDRS")),
		TSAMaxClockUncertainty: defaultTSAMaxClockUncertainty,
		DevelopmentInsecure:    strings.EqualFold(os.Getenv("PKI_DEVELOPMENT_INSECURE"), "true"),
	}
	if raw := strings.TrimSpace(os.Getenv("TSA_MAX_CLOCK_UNCERTAINTY")); raw != "" {
		c.TSAMaxClockUncertainty, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("TSA_MAX_CLOCK_UNCERTAINTY must be a duration: %w", err)
		}
	}

	if c.PublicBaseURL, err = parseHTTPSURL("PUBLIC_BASE_URL", os.Getenv("PUBLIC_BASE_URL"), c.DevelopmentInsecure); err != nil {
		return Config{}, err
	}
	if c.ConsoleBaseURL, err = parseHTTPSURL("CONSOLE_BASE_URL", os.Getenv("CONSOLE_BASE_URL"), c.DevelopmentInsecure); err != nil {
		return Config{}, err
	}
	if c.PublicBaseURL != nil {
		c.PublicHostname = c.PublicBaseURL.Hostname()
	}
	if c.ConsoleBaseURL != nil {
		c.ConsoleHostname = c.ConsoleBaseURL.Hostname()
	}

	secret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(os.Getenv("ROOT_USER_TOTP_SECRET")), " ", ""))
	if secret != "" {
		c.RootUserTOTPSecret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if err != nil {
			return Config{}, fmt.Errorf("ROOT_USER_TOTP_SECRET must be unpadded base32: %w", err)
		}
	}

	if c.MasterKeys, err = parseMasterKeys(os.Getenv("PKI_MASTER_KEYS")); err != nil {
		return Config{}, err
	}
	return c, c.Validate()
}

// Validate enforces invariants before the process opens a listening socket.
func (c Config) Validate() error {
	var missing []string
	for name, value := range map[string]string{
		"DATABASE_URL":             c.DatabaseURL,
		"PUBLIC_BASE_URL":          urlString(c.PublicBaseURL),
		"CONSOLE_BASE_URL":         urlString(c.ConsoleBaseURL),
		"ROOT_USER_EMAIL":          c.RootUserEmail,
		"ROOT_USER_PASSWORD":       c.RootUserPassword,
		"ROOT_USER_TOTP_SECRET":    string(c.RootUserTOTPSecret),
		"PKI_MASTER_KEY_ACTIVE_ID": c.MasterKeyActiveID,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
	if len(c.RootUserPassword) < 32 {
		return errors.New("ROOT_USER_PASSWORD must contain at least 32 characters")
	}
	if c.RootUserPassword == "replace-with-at-least-32-random-characters" {
		return errors.New("ROOT_USER_PASSWORD must not use the example placeholder")
	}
	listenHost, _, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return fmt.Errorf("PKI_LISTEN_ADDRESS must be in host:port form: %w", err)
	}
	if !c.DevelopmentInsecure {
		listenIP := net.ParseIP(listenHost)
		if listenIP == nil || !listenIP.IsLoopback() {
			return errors.New("PKI_LISTEN_ADDRESS must bind an explicit loopback address outside development mode")
		}
	}
	databaseURL, err := url.Parse(c.DatabaseURL)
	if err != nil || (databaseURL.Scheme != "postgres" && databaseURL.Scheme != "postgresql") || databaseURL.Hostname() == "" {
		return errors.New("DATABASE_URL must be a PostgreSQL URL")
	}
	if !c.DevelopmentInsecure && strings.EqualFold(databaseURL.Query().Get("sslmode"), "disable") {
		databaseIP := net.ParseIP(databaseURL.Hostname())
		if databaseIP == nil || !databaseIP.IsLoopback() {
			return errors.New("DATABASE_URL cannot disable TLS outside development mode unless the host is an explicit loopback IP")
		}
	}
	if !c.DevelopmentInsecure {
		databaseIP := net.ParseIP(databaseURL.Hostname())
		if (databaseIP == nil || !databaseIP.IsLoopback()) && databaseURL.Query().Get("sslmode") != "verify-full" {
			return errors.New("remote DATABASE_URL must explicitly use sslmode=verify-full")
		}
	}
	if len(c.RootUserTOTPSecret) < 20 {
		return errors.New("ROOT_USER_TOTP_SECRET must contain at least 160 bits")
	}
	if bytes.Equal(c.RootUserTOTPSecret, make([]byte, len(c.RootUserTOTPSecret))) {
		return errors.New("ROOT_USER_TOTP_SECRET must not use the all-zero example secret")
	}
	if !strings.Contains(c.RootUserEmail, "@") {
		return errors.New("ROOT_USER_EMAIL must be a valid email address")
	}
	if strings.EqualFold(strings.TrimSuffix(c.PublicHostname, "."), strings.TrimSuffix(c.ConsoleHostname, ".")) {
		return errors.New("PUBLIC_BASE_URL and CONSOLE_BASE_URL must use different hostnames")
	}
	if key := c.MasterKeys[c.MasterKeyActiveID]; len(key) != 32 {
		return errors.New("active PKI master key must exist and decode to exactly 32 bytes")
	}
	for _, key := range c.MasterKeys {
		if len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
			return errors.New("PKI_MASTER_KEYS must contain nonzero 32-byte keys, not example keys")
		}
	}
	for _, network := range c.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(network); err != nil {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS contains invalid CIDR %q", network)
		}
	}
	if !c.DevelopmentInsecure && len(c.TrustedProxyCIDRs) == 0 {
		return errors.New("TRUSTED_PROXY_CIDRS is required outside development mode")
	}
	if c.TSAMaxClockUncertainty < time.Millisecond || c.TSAMaxClockUncertainty > time.Minute {
		return errors.New("TSA_MAX_CLOCK_UNCERTAINTY must be between 1ms and 1m")
	}
	return nil
}

func parseMasterKeys(raw string) (map[string][]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("PKI_MASTER_KEYS is required")
	}
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil {
		return nil, fmt.Errorf("PKI_MASTER_KEYS must be a JSON object of base64 keys: %w", err)
	}
	keys := make(map[string][]byte, len(encoded))
	for id, value := range encoded {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("PKI_MASTER_KEYS contains an empty key id")
		}
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("PKI_MASTER_KEYS[%q] must be base64-encoded 32 bytes", id)
		}
		keys[id] = key
	}
	return keys, nil
}

func parseHTTPSURL(name, raw string, allowHTTP bool) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%s must be an absolute origin URL", name)
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("%s must use https", name)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	return u, nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func splitCSV(raw string) []string {
	var out []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func urlString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}
