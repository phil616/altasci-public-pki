package security

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccessVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "max-age=600")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "test-key", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	defer server.Close()

	verifier, err := NewAccessVerifier(server.URL, "application-audience", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	verifier.now = func() time.Time { return now }
	claims := map[string]any{"aud": []string{"application-audience"}, "email": "root@example.com",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Add(-time.Minute).Unix(),
		"iss": server.URL, "sub": "access-user-id", "type": "app"}
	token := signTestJWT(t, key, claims)
	identity, err := verifier.Verify(context.Background(), token, "root@example.com", "ROOT@example.com")
	if err != nil || identity.Subject != "access-user-id" {
		t.Fatalf("verify identity=%#v err=%v", identity, err)
	}
	if _, err := verifier.Verify(context.Background(), token, "attacker@example.com", "root@example.com"); err == nil {
		t.Fatal("expected mismatched Access email header to fail")
	}
	if requests.Load() != 1 {
		t.Fatalf("expected cached JWKS, got %d fetches", requests.Load())
	}

	expired := mapsClone(claims)
	expired["exp"] = now.Add(-time.Minute).Unix()
	if _, err := verifier.Verify(context.Background(), signTestJWT(t, key, expired),
		"root@example.com", "root@example.com"); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mapsClone(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
