package security

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxAccessTokenSize = 32 << 10

// AccessIdentity is the verified identity carried by Cloudflare Access.
type AccessIdentity struct {
	Subject string
	Email   string
}

// AccessVerifier validates application JWTs against Cloudflare's rotating
// account JWKS. It never trusts the email header by itself.
type AccessVerifier struct {
	issuer   string
	audience string
	jwksURL  string
	client   *http.Client
	now      func() time.Time

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

func NewAccessVerifier(teamDomain, audience string, client *http.Client) (*AccessVerifier, error) {
	teamDomain = strings.TrimRight(teamDomain, "/")
	u, err := url.Parse(teamDomain)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" {
		return nil, errors.New("Cloudflare Access team domain must be an https origin")
	}
	if audience == "" {
		return nil, errors.New("Cloudflare Access audience is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &AccessVerifier{
		issuer: teamDomain, audience: audience,
		jwksURL: teamDomain + "/cdn-cgi/access/certs",
		client:  client, now: time.Now, keys: make(map[string]*rsa.PublicKey),
	}, nil
}

// Verify validates the token and requires both Cloudflare-provided email
// representations to match the configured root identity.
func (v *AccessVerifier) Verify(ctx context.Context, token, emailHeader, rootEmail string) (AccessIdentity, error) {
	if token == "" || len(token) > maxAccessTokenSize {
		return AccessIdentity{}, errors.New("missing or oversized Cloudflare Access JWT")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return AccessIdentity{}, errors.New("malformed Cloudflare Access JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AccessIdentity{}, errors.New("malformed JWT header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return AccessIdentity{}, errors.New("JWT must use RS256 and contain kid")
	}
	if header.Type != "" && !strings.EqualFold(header.Type, "JWT") {
		return AccessIdentity{}, errors.New("invalid JWT type")
	}

	key, err := v.key(ctx, header.KeyID, false)
	if err != nil {
		return AccessIdentity{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return AccessIdentity{}, errors.New("malformed JWT signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		// Refresh once to cover a key rotation that reused an unexpectedly stale cache.
		if key, err = v.key(ctx, header.KeyID, true); err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
			return AccessIdentity{}, errors.New("invalid Cloudflare Access JWT signature")
		}
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AccessIdentity{}, errors.New("malformed JWT payload")
	}
	var claims accessClaims
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return AccessIdentity{}, errors.New("malformed JWT claims")
	}
	if err := v.validateClaims(claims); err != nil {
		return AccessIdentity{}, err
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || !strings.EqualFold(email, strings.TrimSpace(emailHeader)) || !strings.EqualFold(email, strings.TrimSpace(rootEmail)) {
		return AccessIdentity{}, errors.New("Cloudflare Access email does not match root identity")
	}
	return AccessIdentity{Subject: claims.Subject, Email: email}, nil
}

type accessClaims struct {
	Audience  json.RawMessage `json:"aud"`
	Email     string          `json:"email"`
	Expires   json.Number     `json:"exp"`
	IssuedAt  json.Number     `json:"iat"`
	NotBefore json.Number     `json:"nbf"`
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Type      string          `json:"type"`
}

func (v *AccessVerifier) validateClaims(c accessClaims) error {
	if c.Issuer != v.issuer || c.Type != "app" || c.Subject == "" {
		return errors.New("invalid Cloudflare Access issuer, type, or subject")
	}
	if !audienceContains(c.Audience, v.audience) {
		return errors.New("Cloudflare Access audience mismatch")
	}
	now := v.now().Unix()
	exp, err := c.Expires.Int64()
	if err != nil || exp <= now-30 {
		return errors.New("Cloudflare Access JWT is expired")
	}
	if c.NotBefore != "" {
		nbf, err := c.NotBefore.Int64()
		if err != nil || nbf > now+30 {
			return errors.New("Cloudflare Access JWT is not yet valid")
		}
	}
	if c.IssuedAt != "" {
		iat, err := c.IssuedAt.Int64()
		if err != nil || iat > now+30 {
			return errors.New("Cloudflare Access JWT has invalid issued-at time")
		}
	}
	return nil
}

func audienceContains(raw json.RawMessage, want string) bool {
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		for _, value := range list {
			if value == want {
				return true
			}
		}
		return false
	}
	var one string
	return json.Unmarshal(raw, &one) == nil && one == want
}

func (v *AccessVerifier) key(ctx context.Context, kid string, force bool) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[kid]
	fresh := v.now().Before(v.expiresAt)
	v.mu.RUnlock()
	if !force && key != nil && fresh {
		return key, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if key = v.keys[kid]; key == nil {
		return nil, errors.New("Cloudflare Access signing key not found")
	}
	return key, nil
}

func (v *AccessVerifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch Cloudflare Access JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch Cloudflare Access JWKS: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var set struct {
		Keys []struct {
			KeyType   string `json:"kty"`
			KeyID     string `json:"kid"`
			Algorithm string `json:"alg"`
			Modulus   string `json:"n"`
			Exponent  string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return errors.New("invalid Cloudflare Access JWKS")
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, item := range set.Keys {
		if item.KeyType != "RSA" || item.KeyID == "" || (item.Algorithm != "" && item.Algorithm != "RS256") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(item.Modulus)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(item.Exponent)
		if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e < 3 {
			continue
		}
		keys[item.KeyID] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: e}
	}
	if len(keys) == 0 {
		return errors.New("Cloudflare Access JWKS contained no usable RS256 keys")
	}
	ttl := 5 * time.Minute
	for _, directive := range strings.Split(resp.Header.Get("Cache-Control"), ",") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "max-age=") {
			if seconds, err := strconv.Atoi(strings.TrimPrefix(directive, "max-age=")); err == nil && seconds > 0 {
				ttl = min(time.Duration(seconds)*time.Second, time.Hour)
			}
		}
	}
	v.mu.Lock()
	v.keys = keys
	v.expiresAt = v.now().Add(ttl)
	v.mu.Unlock()
	return nil
}
