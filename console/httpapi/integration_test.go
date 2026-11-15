package httpapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/auth"
	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/console/tsa"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	dtimestamp "github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"
)

type httpTestTimeSource struct{}

func (httpTestTimeSource) Now(context.Context) (tsa.Moment, error) {
	return tsa.Moment{Time: time.Now().UTC().Truncate(time.Second), Accuracy: 100 * time.Millisecond}, nil
}

func TestHTTPHostsLoginSessionAndCSRF(t *testing.T) {
	databaseURL := os.Getenv("PKI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PKI_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := store.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `TRUNCATE timestamp_tokens, timestamp_authorities, audit_events, audit_chain_heads, ocsp_responses, crls,
        revocations, leaf_key_artifacts, certificates, issuance_jobs, request_approvals,
        certificate_requests, ca_grants, signing_profiles, ocsp_responders, ca_key_versions,
        certificate_authorities, idempotency_keys, sessions, users CASCADE`)
	if err != nil {
		t.Fatal(err)
	}
	data := store.New(pool)
	emptyProfiles, err := data.ListProfiles(ctx, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if emptyProfiles == nil {
		t.Fatal("empty signing profile list must encode as [] rather than null")
	}
	emptyTimestampAuthorities, err := data.ListTimestampAuthorities(ctx, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if emptyTimestampAuthorities == nil {
		t.Fatal("empty timestamp authority list must encode as [] rather than null")
	}
	password := "ordinary-user-password-long-enough"
	hash, _ := security.HashPassword(password)
	user, err := data.CreateUser(ctx, "alice", nil, "user", hash)
	if err != nil {
		t.Fatal(err)
	}
	rootHash, _ := security.HashPassword("0123456789abcdefghijklmnopqrstuvwxyz")
	root, err := data.UpsertRoot(ctx, "root@example.test", rootHash)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("http://pki.example.test")
	consoleURL, _ := url.Parse("http://console.example.test")
	cfg := consoleconfig.Config{DatabaseURL: databaseURL, PublicBaseURL: publicURL, ConsoleBaseURL: consoleURL,
		PublicHostname: publicURL.Hostname(), ConsoleHostname: consoleURL.Hostname(),
		RootUserEmail: "root@example.test", RootUserPassword: "0123456789abcdefghijklmnopqrstuvwxyz",
		RootUserTOTPSecret: bytes.Repeat([]byte{1}, 20),
		MasterKeyActiveID:  "v1", MasterKeys: map[string][]byte{"v1": bytes.Repeat([]byte{2}, 32)},
		SessionIdle: time.Hour, SessionMax: 8 * time.Hour, RootSessionIdle: 15 * time.Minute,
		RootSessionMax: time.Hour, TSAMaxClockUncertainty: 5 * time.Second, DevelopmentInsecure: true}
	authService, err := auth.NewService(data, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pkiService, err := pki.NewService(data, security.Keyring{ActiveID: "v1", Keys: cfg.MasterKeys}, publicURL.String())
	if err != nil {
		t.Fatal(err)
	}
	tsaService, err := tsa.NewService(data, security.Keyring{ActiveID: "v1", Keys: cfg.MasterKeys},
		httpTestTimeSource{})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(cfg, data, authService, pkiService, tsaService, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	handler := api.Handler()
	// Exercise the production authentication path without any gateway headers.
	productionConfig := cfg
	productionConfig.DevelopmentInsecure = false
	productionAPI, err := New(productionConfig, data, authService, pkiService, tsaService,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("standalone root authentication", func(t *testing.T) {
		testStandaloneRootAuth(t, productionAPI.Handler(), cfg)
	})
	rootCA, err := pkiService.CreateRoot(ctx, root, pki.CreateCAInput{Name: "Test Root", Slug: "test-root",
		Subject: pki.Subject{CommonName: "Test Root CA", Organization: "Example"}, PathLength: 1})
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := pkiService.CreateIntermediate(ctx, root, pki.CreateCAInput{Name: "Test Issuer", Slug: "test-issuer",
		ParentCAID: rootCA.ID, Subject: pki.Subject{CommonName: "Test Issuer CA", Organization: "Example"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkiService.GenerateCRL(ctx, intermediate.ID); err != nil {
		t.Fatal(err)
	}
	timestampAuthority, err := tsaService.CreateAuthority(ctx, root, tsa.CreateAuthorityInput{
		CAID: intermediate.ID, Slug: "release-tsa", Name: "Release TSU", PolicyOID: "1.3.6.1.4.1.55555.1.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	timestampRequestDER, err := dtimestamp.CreateRequest(bytes.NewReader([]byte("release artifact")),
		&dtimestamp.RequestOptions{Hash: crypto.SHA256, Certificates: true})
	if err != nil {
		t.Fatal(err)
	}
	timestampRequest := httptest.NewRequest(http.MethodPost,
		"http://pki.example.test/tsa/"+timestampAuthority.Slug, bytes.NewReader(timestampRequestDER))
	timestampRequest.Host = cfg.PublicHostname
	timestampRequest.Header.Set("Content-Type", "application/timestamp-query")
	timestampRecorder := httptest.NewRecorder()
	handler.ServeHTTP(timestampRecorder, timestampRequest)
	if timestampRecorder.Code != http.StatusOK || timestampRecorder.Header().Get("Content-Type") != "application/timestamp-reply" {
		t.Fatalf("timestamp endpoint status=%d type=%q body=%x", timestampRecorder.Code,
			timestampRecorder.Header().Get("Content-Type"), timestampRecorder.Body.Bytes())
	}
	if _, err := dtimestamp.ParseResponse(timestampRecorder.Body.Bytes()); err != nil {
		t.Fatalf("timestamp response is invalid: %v", err)
	}
	csrPEM, _, err := csr.ParseRequest(&csr.CertificateRequest{CN: "api.example.test", Hosts: []string{"api.example.test"},
		KeyRequest: &csr.KeyRequest{A: "rsa", S: 2048}})
	if err != nil {
		t.Fatal(err)
	}
	certificateRequest, err := pkiService.CreateRequest(ctx, user, pki.CreateRequestInput{CAID: intermediate.ID, CSRPEM: string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if err := data.DecideRequest(ctx, certificateRequest.ID, root, "approved", "integration"); err != nil {
		t.Fatal(err)
	}
	issued, err := pkiService.ProcessOne(ctx, "http-integration")
	if err != nil {
		t.Fatal(err)
	}

	loginBody, _ := json.Marshal(map[string]string{"login": "alice", "password": password})
	login := httptest.NewRequest(http.MethodPost, "http://console.example.test/api/v1/auth/login", bytes.NewReader(loginBody))
	login.Host = cfg.ConsoleHostname
	login.RemoteAddr = "127.0.0.1:12345"
	login.Header.Set("Content-Type", "application/json")
	loginRecorder := httptest.NewRecorder()
	handler.ServeHTTP(loginRecorder, login)
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRecorder.Code, loginRecorder.Body.String())
	}
	var loginResponse struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(loginRecorder.Body.Bytes(), &loginResponse); err != nil || loginResponse.CSRFToken == "" {
		t.Fatalf("login response=%s err=%v", loginRecorder.Body.String(), err)
	}
	cookies := loginRecorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != auth.DevelopmentCookieName || !cookies[0].HttpOnly {
		t.Fatalf("invalid session cookie: %#v", cookies)
	}

	session := httptest.NewRequest(http.MethodGet, "http://console.example.test/api/v1/auth/session", nil)
	session.Host = cfg.ConsoleHostname
	session.AddCookie(cookies[0])
	sessionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(sessionRecorder, session)
	if sessionRecorder.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", sessionRecorder.Code, sessionRecorder.Body.String())
	}

	withoutCSRF := httptest.NewRequest(http.MethodPost, "http://console.example.test/api/v1/certificate-requests", bytes.NewReader([]byte(`{}`)))
	withoutCSRF.Host = cfg.ConsoleHostname
	withoutCSRF.AddCookie(cookies[0])
	csrfRecorder := httptest.NewRecorder()
	handler.ServeHTTP(csrfRecorder, withoutCSRF)
	if csrfRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected CSRF rejection, got %d", csrfRecorder.Code)
	}

	idempotentBody, _ := json.Marshal(map[string]any{"ca_id": intermediate.ID, "server_generate_key": true,
		"subject": map[string]string{"common_name": "idempotent.example.test"}, "sans": []string{"idempotent.example.test"}})
	performIdempotent := func(body []byte) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://console.example.test/api/v1/certificate-requests", bytes.NewReader(body))
		request.Host = cfg.ConsoleHostname
		request.AddCookie(cookies[0])
		request.Header.Set("X-CSRF-Token", loginResponse.CSRFToken)
		request.Header.Set("Idempotency-Key", "integration-request-0001")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	firstIdempotent := performIdempotent(idempotentBody)
	secondIdempotent := performIdempotent(idempotentBody)
	if firstIdempotent.Code != http.StatusCreated || secondIdempotent.Code != http.StatusCreated ||
		secondIdempotent.Header().Get("Idempotency-Replayed") != "true" || firstIdempotent.Body.String() != secondIdempotent.Body.String() {
		t.Fatalf("idempotency first=%d second=%d replay=%q", firstIdempotent.Code, secondIdempotent.Code,
			secondIdempotent.Header().Get("Idempotency-Replayed"))
	}
	conflictingBody := bytes.Replace(idempotentBody, []byte("idempotent.example.test"), []byte("different.example.test"), 1)
	if conflict := performIdempotent(conflictingBody); conflict.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	var pendingRequest store.CertificateRequest
	if err := json.Unmarshal(firstIdempotent.Body.Bytes(), &pendingRequest); err != nil {
		t.Fatal(err)
	}
	userInventory, err := data.ListCertificateInventory(ctx, user, "")
	if err != nil || len(userInventory) != 2 {
		t.Fatalf("user inventory len=%d err=%v items=%#v", len(userInventory), err, userInventory)
	}
	userStates := map[string]int{}
	for _, item := range userInventory {
		userStates[item.WorkflowStatus]++
	}
	if userStates["pending"] != 1 || userStates["issued"] != 1 {
		t.Fatalf("user inventory states=%v", userStates)
	}
	inventoryRequest := httptest.NewRequest(http.MethodGet,
		"http://console.example.test/api/v1/certificate-inventory?status=pending", nil)
	inventoryRequest.Host = cfg.ConsoleHostname
	inventoryRequest.AddCookie(cookies[0])
	inventoryRecorder := httptest.NewRecorder()
	handler.ServeHTTP(inventoryRecorder, inventoryRequest)
	if inventoryRecorder.Code != http.StatusOK || !strings.Contains(inventoryRecorder.Body.String(), pendingRequest.ID) {
		t.Fatalf("inventory endpoint status=%d body=%s", inventoryRecorder.Code, inventoryRecorder.Body.String())
	}

	operatorHash, _ := security.HashPassword("operator-password-long-enough")
	operator, err := data.CreateUser(ctx, "operator", nil, "operator", operatorHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := data.GrantCA(ctx, intermediate.ID, operator.ID, "approve", root.ID); err != nil {
		t.Fatal(err)
	}
	if err := data.DecideRequest(ctx, pendingRequest.ID, operator, "rejected", "policy mismatch"); err != nil {
		t.Fatal(err)
	}
	operatorApprovedRequest, err := pkiService.CreateRequest(ctx, user, pki.CreateRequestInput{
		CAID: intermediate.ID, CSRPEM: string(csrPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := data.DecideRequest(ctx, operatorApprovedRequest.ID, operator, "approved", "operator approval"); err != nil {
		t.Fatal(err)
	}
	operatorIssued, err := pkiService.ProcessOne(ctx, "operator-history-integration")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.RevokeCAGrant(ctx, intermediate.ID, operator.ID, "approve"); err != nil {
		t.Fatal(err)
	}
	operatorOwnRequest, err := pkiService.CreateRequest(ctx, operator, pki.CreateRequestInput{
		CAID: intermediate.ID, ServerGenerateKey: true,
		Subject: pki.Subject{CommonName: "operator-owned.example.test"}, SANs: []string{"operator-owned.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	operatorRequests, err := data.ListRequests(ctx, operator)
	if err != nil {
		t.Fatal(err)
	}
	operatorRequestIDs := map[string]bool{}
	for _, item := range operatorRequests {
		operatorRequestIDs[item.ID] = true
	}
	if !operatorRequestIDs[pendingRequest.ID] || !operatorRequestIDs[operatorApprovedRequest.ID] || !operatorRequestIDs[operatorOwnRequest.ID] {
		t.Fatalf("operator request history is incomplete: %#v", operatorRequestIDs)
	}
	operatorCertificates, err := data.ListCertificates(ctx, operator)
	if err != nil || len(operatorCertificates) != 1 || operatorCertificates[0].ID != operatorIssued.Certificate.ID {
		t.Fatalf("operator certificates=%#v err=%v", operatorCertificates, err)
	}
	operatorCanView, err := data.OperatorCanViewCertificate(ctx, operatorIssued.Certificate.ID, operator.ID)
	if err != nil || !operatorCanView {
		t.Fatalf("operator cannot view previously approved certificate: allowed=%v err=%v", operatorCanView, err)
	}
	operatorInventory, err := data.ListCertificateInventory(ctx, operator, "")
	if err != nil || len(operatorInventory) != 3 {
		t.Fatalf("operator inventory len=%d err=%v items=%#v", len(operatorInventory), err, operatorInventory)
	}
	rootInventory, err := data.ListCertificateInventory(ctx, root, "")
	if err != nil || len(rootInventory) != 4 {
		t.Fatalf("root inventory len=%d err=%v items=%#v", len(rootInventory), err, rootInventory)
	}

	publicRequest := httptest.NewRequest(http.MethodGet, "http://pki.example.test/pki/v1/authorities", nil)
	publicRequest.Host = cfg.PublicHostname
	publicRecorder := httptest.NewRecorder()
	handler.ServeHTTP(publicRecorder, publicRequest)
	if publicRecorder.Code != http.StatusOK || publicRecorder.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("public endpoint status=%d headers=%v body=%s", publicRecorder.Code, publicRecorder.Header(), publicRecorder.Body.String())
	}

	issuerRequest := httptest.NewRequest(http.MethodGet, "http://pki.example.test/issuers/test-issuer.cer", nil)
	issuerRequest.Host = cfg.PublicHostname
	issuerRecorder := httptest.NewRecorder()
	handler.ServeHTTP(issuerRecorder, issuerRequest)
	if issuerRecorder.Code != http.StatusOK {
		t.Fatalf("issuer status=%d body=%s", issuerRecorder.Code, issuerRecorder.Body.String())
	}
	issuerCert, err := x509.ParseCertificate(issuerRecorder.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := helpers.ParseCertificatePEM([]byte(issued.Certificate.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	ocspRequestDER, err := ocsp.CreateRequest(leaf, issuerCert, nil)
	if err != nil {
		t.Fatal(err)
	}
	ocspRequest := httptest.NewRequest(http.MethodPost, "http://pki.example.test/ocsp/test-issuer", bytes.NewReader(ocspRequestDER))
	ocspRequest.Host = cfg.PublicHostname
	ocspRecorder := httptest.NewRecorder()
	handler.ServeHTTP(ocspRecorder, ocspRequest)
	parsedResponse, parseErr := ocsp.ParseResponse(ocspRecorder.Body.Bytes(), issuerCert)
	if ocspRecorder.Code != http.StatusOK || parseErr != nil || parsedResponse.Status != ocsp.Good {
		t.Fatalf("OCSP status=%d response=%#v err=%v", ocspRecorder.Code, parsedResponse, parseErr)
	}

	fingerprintRequest := httptest.NewRequest(http.MethodGet,
		"http://pki.example.test/pki/v1/certificates/by-fingerprint/"+hex.EncodeToString(issued.Certificate.FingerprintSHA256), nil)
	fingerprintRequest.Host = cfg.PublicHostname
	fingerprintRecorder := httptest.NewRecorder()
	handler.ServeHTTP(fingerprintRecorder, fingerprintRequest)
	if fingerprintRecorder.Code != http.StatusOK {
		t.Fatalf("fingerprint lookup status=%d body=%s", fingerprintRecorder.Code, fingerprintRecorder.Body.String())
	}

	unknown := httptest.NewRequest(http.MethodGet, "http://unknown.example.test/", nil)
	unknown.Host = "unknown.example.test"
	unknownRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unknownRecorder, unknown)
	if unknownRecorder.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host status=%d", unknownRecorder.Code)
	}
	t.Run("CA import HTTP contract", func(t *testing.T) {
		testHTTPCAImport(t, handler, cfg, data, root, user)
	})
	// Infrastructure failures must never be presented as bad passwords or cause
	// clients to discard otherwise valid sessions.
	pool.Close()
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/v1/auth/login", `{"login":"alice","password":"anything"}`},
		{"GET", "/api/v1/auth/session", ""},
	} {
		r := httptest.NewRequest(tc.method, "http://"+cfg.ConsoleHostname+tc.path, strings.NewReader(tc.body))
		r.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"code":"authentication_unavailable"`) {
			t.Fatalf("database outage was reported as a credential failure: %d %s", w.Code, w.Body.String())
		}
	}
}

// testStandaloneRootAuth checks password/TOTP, replay rejection, secure cookies,
// session authentication, CSRF and credential step-up through the real API.
func testStandaloneRootAuth(t *testing.T, handler http.Handler, cfg consoleconfig.Config) {
	t.Helper()
	forged := httptest.NewRequest("GET", "https://"+cfg.ConsoleHostname+"/api/v1/auth/session", nil)
	forged.Header.Set("Cf-Access-Jwt-Assertion", "forged-gateway-identity")
	forged.Header.Set("Cf-Access-Authenticated-User-Email", cfg.RootUserEmail)
	forged.Header.Set("X-PKI-User-Email", cfg.RootUserEmail)
	forgedResponse := httptest.NewRecorder()
	handler.ServeHTTP(forgedResponse, forged)
	if forgedResponse.Code != http.StatusUnauthorized {
		t.Fatal("legacy gateway headers authenticated a request without a session")
	}
	login := func(password, code string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"login": cfg.RootUserEmail, "password": password, "totp": code})
		r := httptest.NewRequest("POST", "https://"+cfg.ConsoleHostname+"/api/v1/auth/login", bytes.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := login(cfg.RootUserPassword, ""); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"code":"second_factor_required"`) {
		t.Fatalf("root login without TOTP: %d %s", w.Code, w.Body.String())
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha256.New, cfg.RootUserTOTPSecret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	code := fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1_000_000)
	if w := login("wrong-password", code); w.Code != http.StatusUnauthorized {
		t.Fatalf("root login with wrong password: %d", w.Code)
	}
	w := login(cfg.RootUserPassword, code)
	if w.Code != http.StatusOK {
		t.Fatalf("standalone root login: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != auth.CookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("invalid production session cookie: %v", cookies)
	}
	var result struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.CSRFToken == "" {
		t.Fatalf("invalid login response: %s", w.Body.String())
	}
	if replay := login(cfg.RootUserPassword, code); replay.Code != http.StatusUnauthorized {
		t.Fatalf("TOTP replay accepted: %d", replay.Code)
	}
	for _, tc := range []struct {
		method, path, csrf, body string
		status                   int
	}{
		{"GET", "/api/v1/auth/session", "", "", 200},
		{"GET", "/api/v1/users", "", "", 200},
		{"POST", "/api/v1/auth/logout", "", "", 403},
		{"POST", "/api/v1/cas/nonexistent/keys/export", result.CSRFToken, `{"password":"` + cfg.RootUserPassword + `","totp":"` + code + `"}`, 403},
		{"POST", "/api/v1/auth/logout", result.CSRFToken, "", 204},
		{"GET", "/api/v1/auth/session", "", "", 401},
	} {
		r := httptest.NewRequest(tc.method, "https://"+cfg.ConsoleHostname+tc.path, strings.NewReader(tc.body))
		r.AddCookie(cookies[0])
		r.Header.Set("X-CSRF-Token", tc.csrf)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		if recorder.Code != tc.status {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, recorder.Code, recorder.Body.String())
		}
	}
}
