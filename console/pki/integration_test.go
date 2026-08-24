package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"golang.org/x/crypto/ocsp"
)

func TestPostgresIssuanceLifecycle(t *testing.T) {
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
	rootHash, _ := security.HashPassword("0123456789abcdefghijklmnopqrstuvwxyz")
	root, err := data.UpsertRoot(ctx, "root@example.com", rootHash)
	if err != nil {
		t.Fatal(err)
	}
	operatorHash, _ := security.HashPassword("operator-password-long-enough")
	operator, err := data.CreateUser(ctx, "operator", nil, "operator", operatorHash)
	if err != nil {
		t.Fatal(err)
	}
	userHash, _ := security.HashPassword("ordinary-user-password-long-enough")
	user, err := data.CreateUser(ctx, "user", nil, "user", userHash)
	if err != nil {
		t.Fatal(err)
	}

	key := bytes.Repeat([]byte{42}, 32)
	service, err := NewService(data, security.Keyring{ActiveID: "v1", Keys: map[string][]byte{"v1": key}}, "https://pki.example.com")
	if err != nil {
		t.Fatal(err)
	}
	rootCA, err := service.CreateRoot(ctx, root, CreateCAInput{Name: "Enterprise Root",
		Slug: "enterprise-root", Subject: Subject{CommonName: "Enterprise Root CA", Organization: "Example Corp"}, PathLength: 1})
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := service.CreateIntermediate(ctx, root, CreateCAInput{Name: "TLS Issuing CA",
		Slug: "tls-issuing", ParentCAID: rootCA.ID, Subject: Subject{CommonName: "TLS Issuing CA", Organization: "Example Corp"}, PathLength: 0})
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := data.CreateProfile(ctx, store.SigningProfile{CAID: intermediate.ID,
		Name: "internal-tls", Description: "Internal TLS services", DefaultValidity: 24 * time.Hour,
		MaxValidity: 30 * 24 * time.Hour, KeyUsages: []string{"signing", "key encipherment"},
		ExtendedKeyUsages: []string{"server auth"}, AllowedDNSPatterns: []string{"*.example.internal"},
		AllowedIPRanges: []string{"10.0.0.0/8"}, Policy: []byte(`{"owner":"platform"}`), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := data.ListProfiles(ctx, intermediate.ID)
	if err != nil || len(profiles) != 2 {
		t.Fatalf("signing profiles: count=%d err=%v", len(profiles), err)
	}
	for _, permission := range []string{"view_requests", "approve", "issue", "revoke"} {
		if err := data.GrantCA(ctx, intermediate.ID, operator.ID, permission, root.ID); err != nil {
			t.Fatal(err)
		}
	}
	grants, err := data.ListCAGrants(ctx, intermediate.ID)
	if err != nil || len(grants) != 4 {
		t.Fatalf("CA grants: count=%d err=%v", len(grants), err)
	}
	if err := data.GrantCA(ctx, rootCA.ID, operator.ID, "approve", root.ID); err == nil {
		t.Fatal("expected database to reject a root CA grant")
	}

	csrPEM, _, err := csr.ParseRequest(&csr.CertificateRequest{CN: "service.example.internal",
		Hosts: []string{"service.example.internal", "10.0.0.10"}, KeyRequest: &csr.KeyRequest{A: "rsa", S: 2048}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.CreateRequest(ctx, user, CreateRequestInput{CAID: intermediate.ID,
		ProfileID: restricted.ID, CSRPEM: string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if err := data.DecideRequest(ctx, request.ID, user, "approved", "self approve"); err == nil {
		t.Fatal("expected self approval to fail")
	}
	if err := data.DecideRequest(ctx, request.ID, operator, "approved", "approved"); err != nil {
		t.Fatal(err)
	}
	issued, err := service.ProcessOne(ctx, "integration-test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := helpers.ParseCertificatePEM([]byte(issued.Certificate.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := helpers.ParseCertificatePEM([]byte(intermediate.CertificatePEM))
	if err != nil || leaf.CheckSignatureFrom(issuer) != nil {
		t.Fatalf("issued certificate does not chain to intermediate: %v", err)
	}
	if len(leaf.OCSPServer) != 1 || len(leaf.CRLDistributionPoints) != 1 || len(leaf.IssuingCertificateURL) != 1 {
		t.Fatalf("missing publication URIs: OCSP=%v CRL=%v AIA=%v", leaf.OCSPServer, leaf.CRLDistributionPoints, leaf.IssuingCertificateURL)
	}

	revoked, err := service.Revoke(ctx, operator, issued.Certificate.ID, 1, "key compromise")
	if err != nil || revoked.Status != "revoked" {
		t.Fatalf("revoke: cert=%#v err=%v", revoked, err)
	}
	crlDER, _, err := data.CurrentCRL(ctx, intermediate.ID)
	if err != nil {
		t.Fatal(err)
	}
	revocationList, err := x509.ParseRevocationList(crlDER)
	if err != nil || revocationList.CheckSignatureFrom(issuer) != nil || len(revocationList.RevokedCertificateEntries) != 1 {
		t.Fatalf("invalid CRL: entries=%d err=%v", len(revocationList.RevokedCertificateEntries), err)
	}
	ocspDER, err := service.OCSPResponse(ctx, intermediate, revoked, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	parsedOCSP, err := ocsp.ParseResponse(ocspDER, issuer)
	if err != nil || parsedOCSP.Status != ocsp.Revoked || parsedOCSP.RevocationReason != 1 {
		t.Fatalf("invalid OCSP response: %#v err=%v", parsedOCSP, err)
	}

	serverRequest, err := service.CreateRequest(ctx, user, CreateRequestInput{CAID: intermediate.ID,
		ServerGenerateKey: true, Subject: Subject{CommonName: "generated.example.internal"}, SANs: []string{"generated.example.internal"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := data.DecideRequest(ctx, serverRequest.ID, operator, "approved", "approved"); err != nil {
		t.Fatal(err)
	}
	serverIssued, err := service.ProcessOne(ctx, "integration-test")
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, err := service.DownloadLeafKey(ctx, serverIssued.Certificate.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := helpers.ParsePrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := privateKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected RSA private key, got %T", privateKey)
	}
	if _, err := service.DownloadLeafKey(ctx, serverIssued.Certificate.ID, user.ID); err == nil {
		t.Fatal("expected one-time private key to be erased")
	}
	ip := "127.0.0.1"
	role := root.Role
	if err := data.Audit(ctx, store.AuditEvent{ActorUserID: &root.ID, ActorRole: &role,
		Action: "integration.lifecycle", ResourceType: "certificate", ResourceID: &issued.Certificate.ID,
		Outcome: "success", RequestID: "integration-test", SourceIP: &ip,
		Metadata: map[string]any{"serial": issued.Certificate.Serial}}); err != nil {
		t.Fatal(err)
	}
	events, err := data.ListAuditEvents(ctx, 10)
	if err != nil || len(events) != 1 || events[0].Action != "integration.lifecycle" {
		t.Fatalf("audit events: %#v err=%v", events, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET action='tampered'`); err == nil {
		t.Fatal("expected append-only audit trigger to reject an update")
	}
	replacementHash, _ := security.HashPassword("replacement-user-password-long-enough")
	if err := data.ResetUserPassword(ctx, user.ID, replacementHash); err != nil {
		t.Fatal(err)
	}
	refreshedUser, err := data.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if matches, err := security.VerifyPassword("replacement-user-password-long-enough", refreshedUser.PasswordHash); err != nil || !matches {
		t.Fatalf("replacement password did not verify: matches=%v err=%v", matches, err)
	}
}
