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
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/auth"
	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

func testHTTPCAImport(t *testing.T, handler http.Handler, cfg consoleconfig.Config, data *store.Store, root, ordinary store.User) {
	t.Helper()
	ctx := context.Background()
	csrf, csrfHash, err := security.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	sessionCookie := func(user store.User) *http.Cookie {
		token, digest, err := security.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		_, err = data.CreateSession(ctx, user.ID, digest, csrfHash, time.Now().Add(15*time.Minute), time.Now().Add(time.Hour), "127.0.0.1", "import-test")
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.DevelopmentCookieName, Value: token}
	}
	rootCookie, userCookie := sessionCookie(root), sessionCookie(ordinary)
	request := func(input pki.ImportCAInput, cookie *http.Cookie, csrfValue, idempotencyKey, host string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(input)
		r := httptest.NewRequest("POST", "http://"+host+"/api/v1/cas/import", bytes.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("X-CSRF-Token", csrfValue)
		r.Header.Set("Idempotency-Key", idempotencyKey)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9981), Subject: pkix.Name{CommonName: "HTTP Imported Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 1}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	input := pki.ImportCAInput{Name: "HTTP Imported Root", Slug: "http-imported-root", Kind: "root",
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}
	for _, tc := range []struct {
		cookie     *http.Cookie
		csrf, host string
		status     int
	}{
		{nil, "", cfg.ConsoleHostname, 401}, {userCookie, csrf, cfg.ConsoleHostname, 403}, {rootCookie, "", cfg.ConsoleHostname, 403}, {rootCookie, csrf, cfg.PublicHostname, 404},
	} {
		w := request(input, tc.cookie, tc.csrf, "", tc.host)
		if w.Code != tc.status {
			t.Fatalf("import authorization: %d %s", w.Code, w.Body.String())
		}
	}
	w := request(input, rootCookie, csrf, "import-root-request", cfg.ConsoleHostname)
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "private_key_pem") {
		t.Fatalf("import response: %d %s", w.Code, w.Body.String())
	}
	var imported store.CertificateAuthority
	if err := json.Unmarshal(w.Body.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	replay := request(input, rootCookie, csrf, "import-root-request", cfg.ConsoleHostname)
	if replay.Code != 201 || replay.Header().Get("Idempotency-Replayed") != "true" || replay.Body.String() != w.Body.String() {
		t.Fatal("CA import is not idempotent")
	}
	if duplicate := request(input, rootCookie, csrf, "import-root-again", cfg.ConsoleHostname); duplicate.Code != 409 {
		t.Fatalf("duplicate certificate: %d %s", duplicate.Code, duplicate.Body.String())
	}
	invalid := input
	invalid.Slug = "invalid-key"
	invalid.PrivateKeyPEM = "invalid private material"
	if rejected := request(invalid, rootCookie, csrf, "", cfg.ConsoleHostname); rejected.Code != 422 {
		t.Fatalf("invalid key: %d %s", rejected.Code, rejected.Body.String())
	}
	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	childKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	childTemplate := &x509.Certificate{SerialNumber: big.NewInt(9982), Subject: pkix.Name{CommonName: "HTTP Imported Intermediate"}, NotBefore: template.NotBefore, NotAfter: template.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	childDER, err := x509.CreateCertificate(rand.Reader, childTemplate, rootCert, childKey.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	childKeyDER, _ := x509.MarshalPKCS8PrivateKey(childKey)
	childInput := pki.ImportCAInput{Name: "HTTP Imported Intermediate", Slug: "http-imported-intermediate", Kind: "intermediate", ParentCAID: imported.ID,
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: childDER})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: childKeyDER}))}
	child := request(childInput, rootCookie, csrf, "import-child-request", cfg.ConsoleHostname)
	if child.Code != 201 {
		t.Fatalf("import intermediate: %d %s", child.Code, child.Body.String())
	}
	var childCA store.CertificateAuthority
	if err := json.Unmarshal(child.Body.Bytes(), &childCA); err != nil || childCA.ParentCAID == nil || *childCA.ParentCAID != imported.ID {
		t.Fatalf("intermediate response: %s", child.Body.String())
	}
	crlRequest := httptest.NewRequest("GET", "http://"+cfg.PublicHostname+"/crl/"+childCA.Slug+".crl", nil)
	crl := httptest.NewRecorder()
	handler.ServeHTTP(crl, crlRequest)
	if crl.Code != 200 {
		t.Fatalf("imported CA CRL: %d", crl.Code)
	}
	events, err := data.ListAuditEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	success, failure := false, false
	for _, event := range events {
		if event.Action != "ca.import" {
			continue
		}
		encoded, _ := json.Marshal(event)
		if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("invalid private material")) {
			t.Fatal("private key material leaked into audit")
		}
		if event.Outcome == "success" {
			success = true
		}
		if event.Outcome == "failure" {
			failure = true
		}
	}
	if !success || !failure {
		t.Fatal("CA import audit events missing")
	}
	t.Run("audit outage fails closed", func(t *testing.T) {
		_, err := data.Pool().Exec(ctx, `CREATE FUNCTION pki_security_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit outage'; END $$;
            CREATE TRIGGER pki_security_audit_failure BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION pki_security_audit_failure()`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := data.Pool().Exec(context.Background(), `DROP TRIGGER pki_security_audit_failure ON audit_events; DROP FUNCTION pki_security_audit_failure()`); err != nil {
				t.Error(err)
			}
		}()
		denied := request(input, rootCookie, csrf, "audit-outage-import", cfg.ConsoleHostname)
		if denied.Code != 503 || !strings.Contains(denied.Body.String(), "audit_unavailable") {
			t.Fatalf("mutation proceeded without audit: %d %s", denied.Code, denied.Body.String())
		}
		body, _ := json.Marshal(map[string]string{"login": ordinary.Username, "password": "ordinary-user-password-long-enough"})
		r := httptest.NewRequest("POST", "http://"+cfg.ConsoleHostname+"/api/v1/auth/login", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 503 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("login created unaudited session cookie: %d %s", w.Code, w.Body.String())
		}
	})
}
