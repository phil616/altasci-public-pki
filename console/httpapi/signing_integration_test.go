package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/auth"
	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/signing"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/console/tsa"
)

func TestHTTPIndependentSigning(t *testing.T) {
	database := os.Getenv("PKI_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("PKI_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := store.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(ctx, `TRUNCATE audit_events,audit_chain_heads,users CASCADE`); err != nil {
		t.Fatal(err)
	}
	data := store.New(pool)
	password := "independent-signing-password"
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = data.CreateUser(ctx, "independent-owner", nil, "user", hash); err != nil {
		t.Fatal(err)
	}
	public, _ := url.Parse("https://pki.example.test")
	console, _ := url.Parse("https://console.example.test")
	keys := security.Keyring{ActiveID: "v1", Keys: map[string][]byte{"v1": bytes.Repeat([]byte{9}, 32)}}
	cfg := consoleconfig.Config{PublicBaseURL: public, ConsoleBaseURL: console, PublicHostname: public.Hostname(), ConsoleHostname: console.Hostname(), SessionIdle: time.Hour, SessionMax: 24 * time.Hour, MasterKeyActiveID: keys.ActiveID, MasterKeys: keys.Keys, TrustedProxyCIDRs: []string{"127.0.0.1/32"}}
	authService, err := auth.NewService(data, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pkiService, err := pki.NewService(data, keys, public.String())
	if err != nil {
		t.Fatal(err)
	}
	tsaService, err := tsa.NewService(data, keys, httpTestTimeSource{})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server, err := New(cfg, data, authService, pkiService, tsaService, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	csrf := ""
	call := func(host, method, path string, body []byte, bearer, key string, session bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "https://"+host+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if session && cookie != nil {
			req.AddCookie(cookie)
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		return w
	}
	login, _ := json.Marshal(map[string]string{"login": "independent-owner", "password": password})
	w := call(console.Host, "POST", "/api/v1/auth/login", login, "", "", false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie = w.Result().Cookies()[0]
	var logged struct {
		CSRF string `json:"csrf_token"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &logged); err != nil {
		t.Fatal(err)
	}
	csrf = logged.CSRF
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "HTTP Independent CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	policy := signing.Policy{Version: 1, AllowedDNSNames: []string{"www.example.test"}, ExtendedKeyUsages: []string{"server_auth"}, DefaultValiditySeconds: 3600, MaxValiditySeconds: 7200, MaxSANs: 2}
	create := signing.CreateInput{Name: "HTTP instance", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), Policy: policy}
	body, _ := json.Marshal(create)
	if w = call(console.Host, "POST", "/api/v1/signing-instances", body, "", "", false); w.Code != 401 {
		t.Fatal("anonymous management", w.Code)
	}
	w = call(console.Host, "POST", "/api/v1/signing-instances", body, "", "", true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var instance signing.Instance
	if err = json.Unmarshal(w.Body.Bytes(), &instance); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("CA key leaked into response")
	}
	w = call(console.Host, "POST", "/api/v1/signing-instances/"+instance.ID+"/credentials", []byte(`{"name":"external-party","scopes":["issue","read","revoke"],"max_issuances":2}`), "", "", true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var created struct {
		Credential signing.Credential `json:"credential"`
		Token      string             `json:"token"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "www.example.test"}, DNSNames: []string{"www.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(signing.IssueInput{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	endpoint := "/signing/" + instance.ID + "/issue"
	probe := &signingBodyProbe{}
	requestProbe := httptest.NewRequest("POST", "https://"+public.Host+endpoint, probe)
	requestProbe.Header.Set("Authorization", "Bearer ist_"+strings.Repeat("X", 43))
	// Fill all slots: rejecting this request must still be possible immediately.
	for n := 0; n < cap(server.cryptoSlots); n++ {
		server.cryptoSlots <- struct{}{}
	}
	probeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(probeResponse, requestProbe)
	for n := 0; n < cap(server.cryptoSlots); n++ {
		<-server.cryptoSlots
	}
	if probeResponse.Code != 401 || probe.reads.Load() != 0 {
		t.Fatalf("unauthenticated body consumed resources: status=%d reads=%d", probeResponse.Code, probe.reads.Load())
	}

	if w = call(public.Host, "POST", endpoint, body, "", "request-key-0001", true); w.Code != 401 {
		t.Fatal("browser session accepted as bearer", w.Code)
	}
	if w = call(public.Host, "POST", endpoint, body, created.Token, "", false); w.Code != 400 {
		t.Fatal("missing idempotency key", w.Code, w.Body.String())
	}
	if w = call(console.Host, "POST", endpoint, body, created.Token, "request-key-0001", true); w.Code != 404 {
		t.Fatal("public API exposed on console", w.Code)
	}
	w = call(public.Host, "POST", endpoint, body, created.Token, "request-key-0001", false)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var cert signing.Certificate
	if err = json.Unmarshal(w.Body.Bytes(), &cert); err != nil {
		t.Fatal(err)
	}
	w = call(public.Host, "POST", endpoint, body, created.Token, "request-key-0001", false)
	if w.Code != 201 || w.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("idempotent HTTP retry", w.Code)
	}
	if w = call(public.Host, "POST", endpoint, []byte(`{"csr_pem":"x","is_ca":true}`), created.Token, "unknown-field-001", false); w.Code != 400 {
		t.Fatal("unknown input accepted", w.Code)
	}
	path := "/signing/" + instance.ID + "/certificates/" + cert.ID
	if w = call(public.Host, "GET", path, nil, created.Token, "", false); w.Code != 200 {
		t.Fatal("read", w.Code, w.Body.String())
	}
	if w = call(public.Host, "POST", path+"/revoke", []byte(`{"reason":8}`), created.Token, "", false); w.Code != 422 {
		t.Fatal("removeFromCRL accepted", w.Code)
	}
	if w = call(public.Host, "POST", path+"/revoke", []byte(`{"reason":1}`), created.Token, "", false); w.Code != 200 {
		t.Fatal("revoke", w.Code, w.Body.String())
	}
	w = call(public.Host, "GET", "/signing/"+instance.ID+"/crl", nil, "", "", false)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/pkix-crl" {
		t.Fatal("CRL", w.Code, w.Body.String())
	}
	if _, err = x509.ParseRevocationList(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if w = call(public.Host, "GET", "/signing/"+instance.ID+"/issuer.cer", nil, "", "", false); w.Code != 200 {
		t.Fatal("issuer", w.Code)
	}
	// Run the distributed Python client over verified HTTPS and retry its persisted
	// operation after the credential's quota is exhausted.
	if python, lookupErr := exec.LookPath("python3"); lookupErr == nil {
		var redirected atomic.Int32
		trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(200) }))
		defer trap.Close()
		var redirect atomic.Bool
		tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if redirect.Load() {
				http.Redirect(w, r, trap.URL, http.StatusTemporaryRedirect)
				return
			}
			r.Host = public.Host
			server.Handler().ServeHTTP(w, r)
		}))
		defer tlsServer.Close()
		dir := t.TempDir()
		write := func(name string, value []byte) string {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, value, 0600); err != nil {
				t.Fatal(err)
			}
			return path
		}
		caFile := write("transport.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}))
		csrFile := write("request.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
		tokenFile := write("token.txt", []byte(created.Token))
		state := filepath.Join(dir, "operation.json")
		output := filepath.Join(dir, "chain.pem")
		for n := 0; n < 2; n++ {
			cmd := exec.Command(python, "../../scripts/signing-client.py", "issue", "--endpoint", tlsServer.URL+endpoint, "--csr", csrFile, "--token-file", tokenFile, "--state", state, "--output", output, "--ca-file", caFile)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("HTTPS signing client failed: %s %v", out, err)
			}
			if bytes.Contains(out, []byte(created.Token)) {
				t.Fatal("client printed credential")
			}
		}
		redirect.Store(true)
		cmd := exec.Command(python, "../../scripts/signing-client.py", "issue", "--endpoint", tlsServer.URL+endpoint, "--csr", csrFile, "--token-file", tokenFile, "--state", state, "--output", output, "--ca-file", caFile)
		out, redirectErr := cmd.CombinedOutput()
		if redirectErr == nil || redirected.Load() != 0 || bytes.Contains(out, []byte(created.Token)) {
			t.Fatalf("client followed credential redirect or leaked token: %s", out)
		}
		material, err := os.ReadFile(output)
		if err != nil || !bytes.HasPrefix(material, []byte("-----BEGIN CERTIFICATE-----")) {
			t.Fatal("client did not save certificate chain", err)
		}
	}
	w = call(console.Host, "GET", "/api/v1/signing-instances/"+instance.ID+"/credentials", nil, "", "", true)
	if w.Code != 200 || strings.Contains(w.Body.String(), created.Token) {
		t.Fatal("credential list leaked token", w.Code)
	}
	// Preflight is an availability gate, not the authoritative authorization.
	// Revoke while an authenticated request is still uploading its body.
	waiting := &signingBlockingBody{payload: bytes.NewReader(body), entered: make(chan struct{}), release: make(chan struct{})}
	defer waiting.unblock()
	pending := httptest.NewRequest("POST", "https://"+public.Host+endpoint, waiting)
	pending.Header.Set("Authorization", "Bearer "+created.Token)
	pending.Header.Set("Idempotency-Key", "request-key-0001")
	pendingResponse := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); server.Handler().ServeHTTP(pendingResponse, pending) }()
	select {
	case <-waiting.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("authenticated body did not reach the read gate")
	}
	w = call(console.Host, "POST", "/api/v1/signing-instances/"+instance.ID+"/credentials/"+created.Credential.ID+"/revoke", nil, "", "", true)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	waiting.unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pending request did not finish after revocation")
	}
	if pendingResponse.Code != 401 {
		t.Fatalf("authorization was not rechecked after preflight: %d", pendingResponse.Code)
	}

	if w = call(public.Host, "GET", path, nil, created.Token, "", false); w.Code != 401 {
		t.Fatal("revoked token read", w.Code)
	}
	if strings.Contains(logs.String(), created.Token) || strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatal("secret leaked into HTTP logs")
	}
	// Namespace reservation also applies with a mounted frontend.
	server.publicFrontend = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "SPA fallback") })
	w = call(public.Host, "GET", "/signing/unknown", nil, "", "", false)
	if w.Code != 404 || strings.Contains(w.Body.String(), "SPA fallback") {
		t.Fatal("unknown signing API fell through to SPA")
	}
}

// No unauthenticated request may reserve crypto capacity or read a slow body.
type signingBodyProbe struct{ reads atomic.Int32 }

func (b *signingBodyProbe) Read([]byte) (int, error) { b.reads.Add(1); return 0, io.EOF }
func (b *signingBodyProbe) Close() error             { return nil }

type signingBlockingBody struct {
	payload          *bytes.Reader
	entered, release chan struct{}
	start, finish    sync.Once
}

func (b *signingBlockingBody) Read(p []byte) (int, error) {
	b.start.Do(func() { close(b.entered) })
	<-b.release
	return b.payload.Read(p)
}
func (b *signingBlockingBody) Close() error { return nil }
func (b *signingBlockingBody) unblock()     { b.finish.Do(func() { close(b.release) }) }
