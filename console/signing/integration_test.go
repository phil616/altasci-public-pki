package signing

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/pressly/goose/v3"
)

func TestPostgresIndependentSigning(t *testing.T) {
	database := os.Getenv("PKI_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("PKI_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
	owner, err := data.CreateUser(ctx, "sign-owner", nil, "user", "unused-test-hash")
	if err != nil {
		t.Fatal(err)
	}
	other, err := data.CreateUser(ctx, "sign-other", nil, "operator", "unused-test-hash")
	if err != nil {
		t.Fatal(err)
	}
	root, err := data.UpsertRoot(ctx, "sign-root@example.test", "unused-test-hash")
	if err != nil {
		t.Fatal(err)
	}
	keys := security.Keyring{ActiveID: "v1", Keys: map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)}}
	s := New(pool, keys, "https://public.example.test")
	info := RequestInfo{RequestID: "signing-integration", IP: "127.0.0.1", UserAgent: "test"}
	input := testCA(t, nil)
	managed, err := pki.NewService(data, keys, "https://public.example.test")
	if err != nil {
		t.Fatal(err)
	}
	managedCA, err := managed.ImportCA(ctx, root, pki.ImportCAInput{Name: "Managed copy", Slug: "managed-copy", Kind: "root", CertificatePEM: input.CertificatePEM, PrivateKeyPEM: input.PrivateKeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	var managedBefore string
	if err = pool.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM certificate_authorities),(SELECT count(*) FROM ca_key_versions),(SELECT count(*) FROM certificates),(SELECT count(*) FROM revocations),(SELECT count(*) FROM crls),(SELECT count(*) FROM signing_profiles))::text`).Scan(&managedBefore); err != nil {
		t.Fatal(err)
	}
	instance, err := s.Create(ctx, owner.ID, input, info)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := s.Create(ctx, owner.ID, input, info)
	if err != nil {
		t.Fatal("duplicate isolated CA rejected", err)
	}
	if instance.ID == duplicate.ID || bytes.Equal(instance.ciphertext, duplicate.ciphertext) {
		t.Fatal("duplicate CA did not receive independent encryption")
	}
	if _, err = keys.Decrypt(security.Envelope{KeyID: instance.kekID, Nonce: instance.nonce, Ciphertext: instance.ciphertext}, []byte("independent-signing:"+duplicate.ID+":ca-key:v1")); err == nil {
		t.Fatal("cross-instance key substitution succeeded")
	}
	for _, actor := range []string{other.ID, root.ID} {
		if _, err = s.Get(ctx, actor, instance.ID); err == nil {
			t.Fatal("cross-owner instance access")
		}
	}
	encoded, _ := json.Marshal(instance)
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("ciphertext")) {
		t.Fatal("instance response leaked key")
	}
	credential, token, err := s.CreateCredential(ctx, owner.ID, instance.ID, CredentialInput{Name: "single-use", Scopes: []string{"issue", "read", "revoke"}, MaxIssuances: 1}, info)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 47 {
		t.Fatal("token does not have expected entropy encoding")
	}
	request := IssueInput{CSRPEM: testCSR(t, nil)}
	raw, _ := json.Marshal(request)
	if _, _, err = s.Issue(ctx, duplicate.ID, token, "cross-instance-key", request, raw, info); err == nil {
		t.Fatal("cross-instance token authorized")
	}
	var succeeded atomic.Int32
	issued := make(chan Certificate, 8)
	failures := make(chan error, 8)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cert, _, err := s.Issue(ctx, instance.ID, token, fmt.Sprintf("quota-request-%d", n), request, raw, info)
			if err == nil {
				succeeded.Add(1)
				issued <- cert
			} else {
				var fault *Error
				if !errors.As(err, &fault) || fault.Code != "signing_quota_exhausted" {
					failures <- err
				}
			}
		}(n)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if succeeded.Load() != 1 {
		t.Fatalf("atomic single-use quota produced %d certificates", succeeded.Load())
	}
	cert := <-issued
	var used int
	if err = pool.QueryRow(ctx, `SELECT issued_count FROM signing_credentials WHERE id=$1`, credential.ID).Scan(&used); err != nil || used != 1 {
		t.Fatal("quota not persisted", used, err)
	}
	// Discover which concurrent request won, then replay after quota exhaustion.
	var originalKey string
	if err = pool.QueryRow(ctx, `SELECT idempotency_key FROM signing_certificates WHERE id=$1`, cert.ID).Scan(&originalKey); err != nil {
		t.Fatal(err)
	}
	replayed, replay, err := s.Issue(ctx, instance.ID, token, originalKey, request, raw, info)
	if err != nil || !replay || replayed.ID != cert.ID {
		t.Fatal("idempotent recovery after quota exhaustion", err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, token, originalKey, request, append(raw, ' '), info); err == nil {
		t.Fatal("different content reused idempotency key")
	}
	// Reopening the service uses persisted token/issuance state.
	restarted := New(pool, keys, "https://public.example.test")
	if found, err := restarted.PublicCertificate(ctx, instance.ID, cert.ID, token); err != nil || found.ID != cert.ID {
		t.Fatal("restart persistence", err)
	}
	_, otherToken, err := s.CreateCredential(ctx, owner.ID, instance.ID, CredentialInput{Name: "another-party", Scopes: []string{"issue", "read", "revoke"}}, info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PublicCertificate(ctx, instance.ID, cert.ID, otherToken); err == nil {
		t.Fatal("cross-credential read")
	}
	if _, err = s.Revoke(ctx, "", instance.ID, cert.ID, otherToken, 1, info); err == nil {
		t.Fatal("cross-credential revoke")
	}
	if _, err = s.Revoke(ctx, "", instance.ID, cert.ID, token, 1, info); err != nil {
		t.Fatal(err)
	}
	crlDER, err := s.CRL(ctx, instance.ID, info)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerDER, err := s.Issuer(ctx, instance.ID)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	if crl.CheckSignatureFrom(issuer) != nil || len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.String() != cert.Serial || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Fatal("invalid independent CRL")
	}
	var scope bool
	for _, ext := range crl.Extensions {
		if ext.Id.String() == "2.5.29.28" {
			scope = ext.Critical && bytes.Contains(ext.Value, []byte("/signing/"+instance.ID+"/crl"))
		}
	}
	if !scope {
		t.Fatal("CRL does not bind issuer scope")
	}
	cached, err := s.CRL(ctx, instance.ID, info)
	if err != nil || !bytes.Equal(cached, crlDER) {
		t.Fatal("CRL was unnecessarily regenerated", err)
	}
	if openssl, err := exec.LookPath("openssl"); err == nil {
		dir := t.TempDir()
		write := func(name string, value []byte) string {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, value, 0600); err != nil {
				t.Fatal(err)
			}
			return path
		}
		crlPath := write("scope.crl.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))
		caPath := write("ca.pem", []byte(input.CertificatePEM))
		leafPath := write("leaf.pem", []byte(cert.CertificatePEM))
		out, err := exec.Command(openssl, "crl", "-in", crlPath, "-noout", "-text").CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("Only User Certificates")) {
			t.Fatalf("OpenSSL could not parse scoped CRL: %s %v", out, err)
		}
		out, err = exec.Command(openssl, "verify", "-extended_crl", "-CAfile", caPath, "-CRLfile", crlPath, "-crl_check", leafPath).CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("certificate revoked")) {
			t.Fatalf("OpenSSL did not enforce scoped revocation: %s %v", out, err)
		}
		otherCRL, err := s.CRL(ctx, duplicate.ID, info)
		if err != nil {
			t.Fatal(err)
		}
		otherPath := write("other.crl.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: otherCRL}))
		out, err = exec.Command(openssl, "verify", "-extended_crl", "-CAfile", caPath, "-CRLfile", otherPath, "-crl_check", leafPath).CombinedOutput()
		if err == nil {
			t.Fatalf("other instance CRL incorrectly cleared revoked leaf: %s", out)
		}
	}
	if err = s.RevokeCredential(ctx, owner.ID, instance.ID, credential.ID, info); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, token, originalKey, request, raw, info); err == nil {
		t.Fatal("revoked token replay authorized")
	}
	if _, err = s.Update(ctx, owner.ID, instance.ID, UpdateInput{Name: instance.Name, Policy: instance.Policy, Enabled: false}, info); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, otherToken, "disabled-request", request, raw, info); err == nil {
		t.Fatal("disabled issuer signed")
	}
	if _, err = s.CRL(ctx, instance.ID, info); err != nil {
		t.Fatal("suspension stopped CRL publication", err)
	}
	if _, err = s.Update(ctx, owner.ID, instance.ID, UpdateInput{Name: instance.Name, Policy: instance.Policy, Enabled: true}, info); err != nil {
		t.Fatal(err)
	}
	// Audit failure must roll back quota, certificate and idempotency state.
	if _, err = pool.Exec(ctx, `ALTER TABLE audit_events ADD CONSTRAINT signing_audit_test CHECK (request_id<>'signing-block-audit')`); err != nil {
		t.Fatal(err)
	}
	blocked := info
	blocked.RequestID = "signing-block-audit"
	if _, _, err = s.Issue(ctx, instance.ID, otherToken, "audit-rollback-key", request, raw, blocked); err == nil {
		t.Fatal("unaudited issuance returned certificate")
	}
	if _, err = pool.Exec(ctx, `ALTER TABLE audit_events DROP CONSTRAINT signing_audit_test`); err != nil {
		t.Fatal(err)
	}
	if _, replay, err = s.Issue(ctx, instance.ID, otherToken, "audit-rollback-key", request, raw, info); err != nil || replay {
		t.Fatal("audit rollback did not restore fresh request", err)
	}
	// Empty DNS allow-list denies DNS even if another identity category is allowed.
	narrow := testPolicy()
	narrow.AllowedDNSNames = []string{"other.example.test"}
	_, narrowToken, err := s.CreateCredential(ctx, owner.ID, instance.ID, CredentialInput{Name: "restricted", Scopes: []string{"issue"}, Policy: &narrow}, info)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, narrowToken, "restricted-request", request, raw, info); err == nil {
		t.Fatal("credential widened instance policy")
	}
	// Current policy applies to new requests; historical replay does not mint a new certificate.
	tightened := testPolicy()
	tightened.AllowedDNSNames = []string{"only.example.test"}
	if _, err = s.Update(ctx, owner.ID, instance.ID, UpdateInput{Name: instance.Name, Policy: tightened, Enabled: true}, info); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, otherToken, "tightened-policy-key", request, raw, info); err == nil {
		t.Fatal("changed policy was not enforced")
	}
	if _, err = s.Update(ctx, owner.ID, instance.ID, UpdateInput{Name: instance.Name, Policy: instance.Policy, Enabled: true}, info); err != nil {
		t.Fatal(err)
	}
	rateCredential, rateToken, err := s.CreateCredential(ctx, owner.ID, instance.ID, CredentialInput{Name: "rate-test", Scopes: []string{"issue"}, MaxIssuances: 5, RatePerMinute: 1}, info)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, rateToken, "rate-request-one", request, raw, info); err != nil {
		t.Fatal(err)
	}
	if _, replay, err = s.Issue(ctx, instance.ID, rateToken, "rate-request-one", request, raw, info); err != nil || !replay {
		t.Fatal("rate limit blocked historical retry", err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, rateToken, "rate-request-two", request, raw, info); err == nil {
		t.Fatal("per-credential rate limit bypassed")
	} else {
		var fault *Error
		if !errors.As(err, &fault) || fault.Status != 429 {
			t.Fatal("unexpected rate limit result", err)
		}
	}
	if _, err = s.PublicCertificate(ctx, instance.ID, cert.ID, rateToken); err == nil {
		t.Fatal("issue-only token gained read scope")
	}
	if _, err = pool.Exec(ctx, `UPDATE signing_credentials SET rate_window=now()-interval '61 seconds' WHERE id=$1`, rateCredential.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, rateToken, "rate-request-two", request, raw, info); err != nil {
		t.Fatal("rate window did not reset", err)
	}
	if _, err = pool.Exec(ctx, `UPDATE signing_credentials SET expires_at=now()-interval '1 second' WHERE id=$1`, rateCredential.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, rateToken, "rate-request-one", request, raw, info); err == nil {
		t.Fatal("expired credential replay accepted")
	}
	if _, err = pool.Exec(ctx, `UPDATE signing_certificates SET instance_id=$2 WHERE id=$1`, cert.ID, duplicate.ID); err == nil {
		t.Fatal("cross-instance credential FK was not enforced")
	}
	if _, err = pool.Exec(ctx, `UPDATE signing_instances SET crl_der=NULL,crl_next_update=NULL WHERE id=$1`, instance.ID); err != nil {
		t.Fatal(err)
	}
	upperCRL, err := s.CRL(ctx, strings.ToUpper(instance.ID), info)
	if err != nil {
		t.Fatal(err)
	}
	parsedUpper, err := x509.ParseRevocationList(upperCRL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range parsedUpper.Extensions {
		if ext.Id.String() == "2.5.29.28" && !bytes.Contains(ext.Value, []byte("/signing/"+instance.ID+"/crl")) {
			t.Fatal("noncanonical request poisoned cached CRL scope")
		}
	}
	// Wrong encryption context cannot sign or consume quota.
	if _, err = pool.Exec(ctx, `UPDATE signing_instances SET encrypted_key=$2,key_nonce=$3 WHERE id=$1`, instance.ID, duplicate.ciphertext, duplicate.nonce); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, otherToken, "key-substitution-test", request, raw, info); err == nil {
		t.Fatal("substituted key signed a certificate")
	}
	if _, err = pool.Exec(ctx, `UPDATE signing_instances SET encrypted_key=$2,key_nonce=$3 WHERE id=$1`, instance.ID, instance.ciphertext, instance.nonce); err != nil {
		t.Fatal(err)
	}
	oldNow := s.now
	s.now = func() time.Time { return time.Now().Add(49 * time.Hour) }
	_, _, expiredErr := s.Issue(ctx, instance.ID, otherToken, "expired-ca-test", request, raw, info)
	s.now = oldNow
	if expiredErr == nil {
		t.Fatal("expired CA signed a certificate")
	}
	page, cursor, err := s.Certificates(ctx, owner.ID, instance.ID, "", 1)
	if err != nil || len(page) != 1 || cursor == "" {
		t.Fatal("certificate pagination", err)
	}
	nextPage, _, err := s.Certificates(ctx, owner.ID, instance.ID, cursor, 1)
	if err != nil || len(nextPage) != 1 || nextPage[0].ID == page[0].ID {
		t.Fatal("cursor repeated a certificate", err)
	}
	db, err := sql.Open("pgx", database)
	if err != nil {
		t.Fatal(err)
	}
	// Target the signing migration explicitly, even when newer migrations exist.
	downgradeErr := goose.DownToContext(ctx, db, "migrations", 3)
	_ = db.Close()
	if err := store.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	if downgradeErr == nil {
		t.Fatal("destructive downgrade accepted protected signing data")
	}
	if _, err = pool.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Issue(ctx, instance.ID, otherToken, "disabled-owner-key", request, raw, info); err == nil {
		t.Fatal("disabled owner credential remained authorized")
	}
	if _, err = s.CRL(ctx, instance.ID, info); err != nil {
		t.Fatal("disabled owner stopped CRL publication", err)
	}
	var managedAfter string
	if err = pool.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM certificate_authorities),(SELECT count(*) FROM ca_key_versions),(SELECT count(*) FROM certificates),(SELECT count(*) FROM revocations),(SELECT count(*) FROM crls),(SELECT count(*) FROM signing_profiles))::text`).Scan(&managedAfter); err != nil {
		t.Fatal(err)
	}
	if managedBefore != managedAfter {
		t.Fatal("independent feature modified managed PKI tables", managedBefore, managedAfter)
	}
	preserved, err := data.CAByID(ctx, managedCA.ID)
	if err != nil || preserved.CertificatePEM != input.CertificatePEM {
		t.Fatal("managed duplicate CA changed", err)
	}
}
