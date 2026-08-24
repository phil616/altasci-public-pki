package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	consoleconfig "github.com/cloudflare/cfssl/console/config"
)

func TestOriginGatewayAuthenticatesAndRestoresRequest(t *testing.T) {
	secret := bytes.Repeat([]byte{0xab}, 32)
	server := &Server{config: consoleconfig.Config{
		PublicHostname:     "pki.altasci.com",
		ConsoleHostname:    "pki-console.altasci.com",
		OriginSharedSecret: secret,
		TrustedProxyCIDRs:  []string{"127.0.0.1/32"},
	}}
	var received *http.Request
	handler := server.requireOriginGateway(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Clone(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://pki-origin.altasci.com/api/v1/auth/session", nil)
	request.RemoteAddr = "127.0.0.1:45678"
	request.Header.Set("X-PKI-Origin-Secret", "abababababababababababababababababababababababababababababababab")
	request.Header.Set("X-PKI-Forwarded-Host", "PKI-CONSOLE.ALTASCI.COM")
	request.Header.Set("X-PKI-Client-IP", "2001:db8::7")
	request.Header.Set("X-PKI-Access-Authenticated-User-Email", " Phil616@163.com ")
	request.Header.Set("Cf-Access-Authenticated-User-Email", "attacker@example.com")
	request.Header.Set("Cf-Access-Jwt-Assertion", "signed-user-token")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent || received == nil {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if received.Host != "pki-console.altasci.com" || received.Header.Get("Cf-Connecting-Ip") != "2001:db8::7" {
		t.Fatalf("request was not restored: host=%q ip=%q", received.Host, received.Header.Get("Cf-Connecting-Ip"))
	}
	if received.Header.Get("X-PKI-Origin-Secret") != "" || received.Header.Get("X-PKI-Forwarded-Host") != "" || received.Header.Get("X-PKI-Access-Authenticated-User-Email") != "" {
		t.Fatal("internal origin headers reached the application")
	}
	if received.Header.Get("Cf-Access-Authenticated-User-Email") != "phil616@163.com" {
		t.Fatalf("Cloudflare Access email was not safely restored: %q", received.Header.Get("Cf-Access-Authenticated-User-Email"))
	}
	if received.Header.Get("Cf-Access-Jwt-Assertion") != "signed-user-token" {
		t.Fatal("Cloudflare Access identity was not preserved")
	}
}

func TestOriginGatewayRejectsUntrustedRequests(t *testing.T) {
	server := &Server{config: consoleconfig.Config{
		PublicHostname:     "pki.altasci.com",
		ConsoleHostname:    "pki-console.altasci.com",
		OriginSharedSecret: bytes.Repeat([]byte{0xab}, 32),
		TrustedProxyCIDRs:  []string{"127.0.0.1/32"},
	}}
	handler := server.requireOriginGateway(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("rejected request reached the application")
	}))
	tests := []struct {
		name       string
		remoteAddr string
		secret     string
		host       string
		wantStatus int
	}{
		{name: "missing secret", remoteAddr: "127.0.0.1:1", host: "pki.altasci.com", wantStatus: http.StatusForbidden},
		{name: "wrong secret", remoteAddr: "127.0.0.1:1", secret: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", host: "pki.altasci.com", wantStatus: http.StatusForbidden},
		{name: "untrusted proxy", remoteAddr: "192.0.2.10:1", secret: "abababababababababababababababababababababababababababababababab", host: "pki.altasci.com", wantStatus: http.StatusForbidden},
		{name: "unknown host", remoteAddr: "127.0.0.1:1", secret: "abababababababababababababababababababababababababababababababab", host: "attacker.example", wantStatus: http.StatusMisdirectedRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://pki-origin.altasci.com/health/live", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("X-PKI-Origin-Secret", test.secret)
			request.Header.Set("X-PKI-Forwarded-Host", test.host)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
}

func TestOriginGatewayDoesNotBridgeAccessEmailForPublicHost(t *testing.T) {
	server := &Server{config: consoleconfig.Config{
		PublicHostname:     "pki.altasci.com",
		ConsoleHostname:    "pki-console.altasci.com",
		OriginSharedSecret: bytes.Repeat([]byte{0xab}, 32),
		TrustedProxyCIDRs:  []string{"127.0.0.1/32"},
	}}
	handler := server.requireOriginGateway(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if email := r.Header.Get("Cf-Access-Authenticated-User-Email"); email != "" {
			t.Fatalf("Access email leaked to public application host: %q", email)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://pki-origin.altasci.com/health/live", nil)
	request.RemoteAddr = "127.0.0.1:45678"
	request.Header.Set("X-PKI-Origin-Secret", "abababababababababababababababababababababababababababababababab")
	request.Header.Set("X-PKI-Forwarded-Host", "pki.altasci.com")
	request.Header.Set("X-PKI-Access-Authenticated-User-Email", "phil616@163.com")
	request.Header.Set("Cf-Access-Authenticated-User-Email", "attacker@example.com")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestOriginGatewayIsDisabledOnlyForDevelopment(t *testing.T) {
	server := &Server{config: consoleconfig.Config{DevelopmentInsecure: true}}
	called := false
	handler := server.requireOriginGateway(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://pki.localhost/health/live", nil))
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("development request was blocked: status=%d", recorder.Code)
	}
}
