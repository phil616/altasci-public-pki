package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	consoleconfig "github.com/cloudflare/cfssl/console/config"
)

func TestEmbeddedFrontendHostRouting(t *testing.T) {
	consoleURL, _ := url.Parse("https://admin.example.test")
	publicURL, _ := url.Parse("https://certs.example.test")
	s := &Server{config: consoleconfig.Config{
		ConsoleBaseURL: consoleURL, PublicBaseURL: publicURL,
		ConsoleHostname: consoleURL.Hostname(), PublicHostname: publicURL.Hostname(),
	}, console: http.NewServeMux(), public: http.NewServeMux()}
	s.routes()
	assets := fstest.MapFS{
		"index.html":          {Data: []byte("<!doctype html>" + surfaceMarker + `<div id="root"></div>`)},
		"assets/app-hash.js":  {Data: []byte("console.log('embedded')")},
		".vite/manifest.json": {Data: []byte("private manifest")},
	}
	if err := s.MountFrontend(assets); err != nil {
		t.Fatal(err)
	}
	handler := s.securityHeaders(http.HandlerFunc(s.dispatch))
	for _, tc := range []struct {
		host, method, path, body string
		status                   int
	}{
		{"admin.example.test", "GET", "/", `content="console"`, 200},
		{"admin.example.test", "GET", "/authorities/some-id", `content="console"`, 200},
		{"certs.example.test", "GET", "/lookup", `content="public"`, 200},
		{"certs.example.test", "HEAD", "/lookup", "", 200},
		{"admin.example.test", "GET", "/api/v1/health/live", `"status":"ok"`, 200},
		{"admin.example.test", "GET", "/api/v1/auth/session", "authentication_required", 401},
		{"certs.example.test", "GET", "/api/v1/auth/session", "404", 404},
		{"admin.example.test", "GET", "/api/v1/missing", "404", 404},
		{"admin.example.test", "GET", "/api/v1/auth/login", "Method Not Allowed", 405},
		{"certs.example.test", "GET", "/tsa/some-authority", "Method Not Allowed", 405},
		{"admin.example.test", "GET", "/pki/v1/authorities", "404", 404},
		{"certs.example.test", "GET", "/pki/v1/missing", "404", 404},
		{"certs.example.test", "GET", "/ocsp/missing", "Temporary Redirect", 307},
		{"certs.example.test", "GET", "/ocsp", "404", 404},
		{"admin.example.test", "POST", "/login", "Method not allowed", 405},
		{"admin.example.test", "GET", "/assets/app-hash.js", "embedded", 200},
		{"admin.example.test", "GET", "/assets/missing.js", "404", 404},
		{"admin.example.test", "GET", "/assets/missing", "404", 404},
		{"admin.example.test", "GET", "/.vite/manifest.json", "404", 404},
		{"attacker.example.test", "GET", "/", "unknown_host", 421},
	} {
		t.Run(tc.host+tc.method+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "<!doctype html>") {
				if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") || w.Header().Get("Cache-Control") != "no-cache" {
					t.Fatalf("incorrect SPA headers: %v", w.Header())
				}
			}
			if tc.path == "/assets/app-hash.js" && !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
				t.Fatal("hashed assets should be cached")
			}
		})
	}
}

func TestFrontendRequiresBuild(t *testing.T) {
	s := &Server{}
	if err := s.MountFrontend(fstest.MapFS{}); err == nil {
		t.Fatal("missing frontend build accepted")
	}
}

func TestClientIPTrustsOnlyConfiguredProxy(t *testing.T) {
	s := &Server{config: consoleconfig.Config{TrustedProxyCIDRs: []string{"127.0.0.1/32"}}}
	r := httptest.NewRequest("GET", "https://admin.example.test/", nil)
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	r.Header.Set("Cf-Connecting-Ip", "203.0.113.9")
	r.RemoteAddr = "192.0.2.1:1234"
	if got := s.clientIP(r); got != "192.0.2.1" {
		t.Fatalf("untrusted proxy changed client IP: %s", got)
	}
	r.RemoteAddr = "127.0.0.1:1234"
	if got := s.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("trusted proxy IP not used: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.7")
	if got := s.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("attacker XFF prefix spoofed client IP: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "invalid")
	if got := s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("invalid forwarded IP accepted: %s", got)
	}
}
