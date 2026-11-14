package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"golang.org/x/crypto/ocsp"
)

func TestPostgresCAImport(t *testing.T) {
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
	actor, err := data.UpsertRoot(ctx, "root@example.test", "unused-test-hash")
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, "requester", nil, "user", "unused-test-hash")
	if err != nil {
		t.Fatal(err)
	}
	keyring := security.Keyring{ActiveID: "v1", Keys: map[string][]byte{"v1": bytes.Repeat([]byte{3}, 32)}}
	service, err := NewService(data, keyring, "https://pki.example.test")
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootMaterial := newImportTestCA(t, nil, rsaKey, nil)
	rootInput := importTestInput(rootMaterial)
	root, err := service.ImportCA(ctx, actor, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	if root.CertificatePEM != rootMaterial.certPEM || root.ChainPEM != rootMaterial.certPEM || root.PathLength != -1 || root.ParentCAID != nil {
		t.Fatal("import changed the original root certificate or constraints")
	}
	storedKey, err := data.ActiveCAKey(ctx, root.ID)
	if err != nil || storedKey.Algorithm != "RSA-2048" {
		t.Fatalf("RSA-2048 key persistence: %v %s", err, storedKey.Algorithm)
	}
	plain, err := keyring.Decrypt(security.Envelope{KeyID: storedKey.KEKID, Nonce: storedKey.Nonce, Ciphertext: storedKey.EncryptedPKCS8}, caKeyAAD(root.ID, 1))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(plain, storedKey.EncryptedPKCS8) || bytes.Contains(storedKey.EncryptedPKCS8, []byte("PRIVATE KEY")) {
		t.Fatal("CA key was not encrypted")
	}
	exported, err := service.ExportCAKey(ctx, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair([]byte(root.CertificatePEM), exported); err != nil {
		t.Fatalf("exported imported key: %v", err)
	}
	duplicate := rootInput
	duplicate.Slug = "same-cert-different-slug"
	if _, err := service.ImportCA(ctx, actor, duplicate); !errors.Is(err, ErrCAConflict) {
		t.Fatalf("duplicate certificate accepted: %v", err)
	}
	conflict := importTestInput(newImportTestCA(t, nil, nil, nil))
	if _, err := service.ImportCA(ctx, actor, conflict); !errors.Is(err, ErrCAConflict) {
		t.Fatalf("duplicate slug accepted: %v", err)
	}
	if _, err := service.ImportCA(ctx, user, rootInput); err == nil {
		t.Fatal("ordinary user imported CA")
	}
	// A newly created intermediate can use an imported root with no path limit.
	if _, err := service.CreateIntermediate(ctx, actor, CreateCAInput{Name: "Generated Issuer", Slug: "generated-issuer", ParentCAID: root.ID, Subject: Subject{CommonName: "Generated Issuer"}}); err != nil {
		t.Fatalf("new intermediate under imported root: %v", err)
	}
	parentMaterial := newImportTestCA(t, rootMaterial, nil, func(c *x509.Certificate) { c.MaxPathLen = 1 })
	parentInput := importTestInput(parentMaterial)
	parentInput.Kind = "intermediate"
	parentInput.ParentCAID = root.ID
	parentInput.Slug = "imported-parent"
	parent, err := service.ImportCA(ctx, actor, parentInput)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial := newImportTestCA(t, parentMaterial, nil, func(c *x509.Certificate) { c.MaxPathLen = 0; c.MaxPathLenZero = true })
	issuerInput := importTestInput(issuerMaterial)
	issuerInput.Kind = "intermediate"
	issuerInput.ParentCAID = parent.ID
	issuerInput.Slug = "imported-issuer"
	issuer, err := service.ImportCA(ctx, actor, issuerInput)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.ChainPEM != issuerMaterial.certPEM+parentMaterial.certPEM+rootMaterial.certPEM || issuer.PathLength != 0 {
		t.Fatal("imported intermediate chain changed")
	}
	responder, err := data.ActiveOCSPResponder(ctx, issuer.ID)
	if err != nil {
		t.Fatal(err)
	}
	responderCert, err := helpers.ParseCertificatePEM([]byte(responder.CertificatePEM))
	if err != nil || responderCert.CheckSignatureFrom(issuerMaterial.cert) != nil {
		t.Fatalf("imported issuer OCSP responder: %v", err)
	}
	requestPEM, _, err := csr.ParseRequest(&csr.CertificateRequest{CN: "import.example.test", Hosts: []string{"import.example.test"}, KeyRequest: &csr.KeyRequest{A: "ecdsa", S: 256}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.CreateRequest(ctx, user, CreateRequestInput{CAID: issuer.ID, CSRPEM: string(requestPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if err := data.DecideRequest(ctx, request.ID, actor, "approved", "import lifecycle"); err != nil {
		t.Fatal(err)
	}
	issued, err := service.ProcessOne(ctx, "import-test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := helpers.ParseCertificatePEM([]byte(issued.Certificate.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(rootMaterial.cert)
	intermediates.AddCert(parentMaterial.cert)
	intermediates.AddCert(issuerMaterial.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "import.example.test"}); err != nil {
		t.Fatalf("imported hierarchy issued invalid certificate: %v", err)
	}
	response, err := service.OCSPResponse(ctx, issuer, issued.Certificate, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ocsp.ParseResponseForCert(response, leaf, issuerMaterial.cert); err != nil || parsed.Status != ocsp.Good {
		t.Fatalf("imported issuer OCSP: %v", err)
	}
	if _, err := service.Revoke(ctx, actor, issued.Certificate.ID, 1, "import revocation"); err != nil {
		t.Fatal(err)
	}
	crlDER, err := service.GenerateCRL(ctx, issuer.ID)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil || crl.CheckSignatureFrom(issuerMaterial.cert) != nil || len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("imported issuer CRL: %v", err)
	}
	if crl.Number == nil || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Fatal("CRL number or revocation reason missing")
	}
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := service.GenerateCRL(ctx, issuer.ID); err != nil {
				t.Errorf("concurrent CRL publication: %v", err)
			}
		}()
	}
	group.Wait()
	current, _, err := data.CurrentCRL(ctx, issuer.ID)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := x509.ParseRevocationList(current)
	if err != nil || latest.Number.Int64() != crl.Number.Int64()+4 {
		t.Fatalf("CRL sequence lost an update: %v", err)
	}
	t.Run("validity overflow", func(t *testing.T) {
		validity := int64(math.MaxInt64)
		if _, err := service.CreateRequest(ctx, user, CreateRequestInput{CAID: issuer.ID, CSRPEM: string(requestPEM), RequestedValiditySeconds: &validity}); err == nil {
			t.Fatal("overflowing validity accepted")
		}
	})
	t.Run("worker recovery and key retry", func(t *testing.T) {
		req, err := service.CreateRequest(ctx, user, CreateRequestInput{CAID: issuer.ID, ServerGenerateKey: true, Subject: Subject{CommonName: "recovered.example.test"}, SANs: []string{"recovered.example.test"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := data.DecideRequest(ctx, req.ID, actor, "approved", "recover"); err != nil {
			t.Fatal(err)
		}
		jobID, requestID, err := data.ClaimIssuanceJob(ctx, "dead-worker")
		if err != nil {
			t.Fatal(err)
		}
		if requestID != req.ID {
			t.Fatal("wrong job claimed")
		}
		_, err = pool.Exec(ctx, `UPDATE issuance_jobs SET locked_at=now()-interval '6 minutes' WHERE id=$1`, jobID)
		if err != nil {
			t.Fatal(err)
		}
		reclaimed, reclaimedRequest, err := data.ClaimIssuanceJob(ctx, "new-worker")
		if err != nil || reclaimed != jobID || reclaimedRequest != requestID {
			t.Fatalf("stale job was not recovered: %v", err)
		}
		if err := data.FailIssuance(ctx, jobID, requestID, "dead-worker", "stale", false); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("stale worker changed job state: %v", err)
		}
		_, err = pool.Exec(ctx, `UPDATE issuance_jobs SET locked_at=now()-interval '6 minutes' WHERE id=$1`, jobID)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.ProcessOne(ctx, "recovery-worker")
		if err != nil {
			t.Fatal(err)
		}
		if err := data.FailIssuance(ctx, jobID, requestID, "new-worker", "stale", false); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("late failure changed succeeded job")
		}
		missingKeyService, err := NewService(data, security.Keyring{ActiveID: "v2", Keys: map[string][]byte{"v2": bytes.Repeat([]byte{9}, 32)}}, "https://pki.example.test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := missingKeyService.DownloadLeafKey(ctx, result.Certificate.ID, user.ID); err == nil {
			t.Fatal("key decrypted with missing KEK")
		}
		if _, err := service.DownloadLeafKey(ctx, result.Certificate.ID, user.ID); err != nil {
			t.Fatalf("decryption failure destroyed one-time key: %v", err)
		}
		if _, err := service.DownloadLeafKey(ctx, result.Certificate.ID, user.ID); err == nil {
			t.Fatal("one-time key downloaded twice")
		}
	})
	t.Run("imported name constraints and ancestor expiry", func(t *testing.T) {
		rootMaterial := newImportTestCA(t, nil, nil, func(c *x509.Certificate) {
			c.PermittedDNSDomainsCritical = true
			c.PermittedDNSDomains = []string{"allowed.example.test"}
			c.NotAfter = time.Now().Add(2 * time.Hour)
		})
		rootInput := importTestInput(rootMaterial)
		rootInput.Slug = "constrained-root"
		rootCA, err := service.ImportCA(ctx, actor, rootInput)
		if err != nil {
			t.Fatal(err)
		}
		issuerMaterial := newImportTestCA(t, rootMaterial, nil, func(c *x509.Certificate) { c.MaxPathLenZero = true; c.MaxPathLen = 0 })
		issuerInput := importTestInput(issuerMaterial)
		issuerInput.Kind = "intermediate"
		issuerInput.ParentCAID = rootCA.ID
		issuerInput.Slug = "constrained-issuer"
		issuerCA, err := service.ImportCA(ctx, actor, issuerInput)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"blocked.other.test", "host.allowed.example.test"} {
			req, err := service.CreateRequest(ctx, user, CreateRequestInput{CAID: issuerCA.ID, ServerGenerateKey: true, Subject: Subject{CommonName: name}, SANs: []string{name}})
			if err != nil {
				t.Fatal(err)
			}
			if err := data.DecideRequest(ctx, req.ID, actor, "approved", "constraints"); err != nil {
				t.Fatal(err)
			}
			result, err := service.ProcessOne(ctx, "constraint-worker")
			if name == "blocked.other.test" {
				if err == nil {
					t.Fatal("issued outside imported CA name constraints")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Certificate.NotAfter.After(rootMaterial.cert.NotAfter) {
				t.Fatal("leaf outlives root CA")
			}
		}
	})
}
