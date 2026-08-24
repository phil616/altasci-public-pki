// Package pki implements PKI-Console workflows by calling CFSSL Go packages
// directly. No CFSSL subprocesses or legacy unauthenticated handlers are used.
package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	cfconfig "github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	cfcrl "github.com/cloudflare/cfssl/crl"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"golang.org/x/crypto/ocsp"
)

const (
	rootValidity         = 10 * 365 * 24 * time.Hour
	intermediateValidity = 3 * 365 * 24 * time.Hour
	leafDefaultValidity  = 90 * 24 * time.Hour
	leafMaxValidity      = 397 * 24 * time.Hour
	certificateBackdate  = 5 * time.Minute
)

type Service struct {
	store         *store.Store
	keys          security.Keyring
	publicBaseURL string
	now           func() time.Time
}

type Subject struct {
	CommonName         string `json:"common_name"`
	Country            string `json:"country,omitempty"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
}

type CreateCAInput struct {
	Name       string  `json:"name"`
	Slug       string  `json:"slug"`
	Subject    Subject `json:"subject"`
	ParentCAID string  `json:"parent_ca_id,omitempty"`
	PathLength int     `json:"path_length"`
}

type CreateRequestInput struct {
	CAID                     string   `json:"ca_id"`
	ProfileID                string   `json:"profile_id,omitempty"`
	CSRPEM                   string   `json:"csr_pem,omitempty"`
	Subject                  Subject  `json:"subject"`
	SANs                     []string `json:"sans"`
	ServerGenerateKey        bool     `json:"server_generate_key"`
	RequestedValiditySeconds *int64   `json:"requested_validity_seconds,omitempty"`
}

type IssueResult struct {
	Certificate store.Certificate
}

func NewService(s *store.Store, keys security.Keyring, publicBaseURL string) (*Service, error) {
	if s == nil {
		return nil, errors.New("PKI store is required")
	}
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if _, err := url.ParseRequestURI(publicBaseURL); err != nil {
		return nil, errors.New("invalid public base URL")
	}
	return &Service{store: s, keys: keys, publicBaseURL: strings.TrimRight(publicBaseURL, "/"), now: time.Now}, nil
}

func (s *Service) CreateRoot(ctx context.Context, actor store.User, input CreateCAInput) (store.CertificateAuthority, error) {
	if actor.Role != "super_admin" {
		return store.CertificateAuthority{}, errors.New("only the super administrator may create root CAs")
	}
	if err := validateCAInput(input, true); err != nil {
		return store.CertificateAuthority{}, err
	}
	caID, keyID, profileID, err := s.newIDs(ctx)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	req := &csr.CertificateRequest{
		CN:         input.Subject.CommonName,
		Names:      []csr.Name{subjectName(input.Subject)},
		KeyRequest: &csr.KeyRequest{A: "rsa", S: 4096},
		CA: &csr.CAConfig{PathLength: input.PathLength, PathLenZero: input.PathLength == 0,
			Expiry: durationString(rootValidity), Backdate: durationString(certificateBackdate)},
	}
	certPEM, _, keyPEM, err := initca.New(req)
	if err != nil {
		return store.CertificateAuthority{}, fmt.Errorf("CFSSL create root CA: %w", err)
	}
	return s.persistCA(ctx, actor, input, "root", nil, caID, keyID, profileID, certPEM, certPEM, keyPEM, rootValidity)
}

func (s *Service) CreateIntermediate(ctx context.Context, actor store.User, input CreateCAInput) (store.CertificateAuthority, error) {
	if actor.Role != "super_admin" {
		return store.CertificateAuthority{}, errors.New("only the super administrator may issue intermediate CAs")
	}
	if err := validateCAInput(input, false); err != nil {
		return store.CertificateAuthority{}, err
	}
	parent, err := s.store.CAByID(ctx, input.ParentCAID)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	if parent.Kind != "root" || parent.Status != "active" {
		return store.CertificateAuthority{}, errors.New("intermediate parent must be an active root CA")
	}
	parentCert, parentKey, err := s.loadSigner(ctx, parent)
	if err != nil {
		return store.CertificateAuthority{}, err
	}

	request := &csr.CertificateRequest{
		CN:         input.Subject.CommonName,
		Names:      []csr.Name{subjectName(input.Subject)},
		KeyRequest: &csr.KeyRequest{A: "rsa", S: 3072},
		CA:         &csr.CAConfig{PathLength: input.PathLength, PathLenZero: input.PathLength == 0},
		CRL:        s.publicBaseURL + "/crl/" + input.Slug + ".crl",
	}
	csrPEM, keyPEM, err := csr.ParseRequest(request)
	if err != nil {
		return store.CertificateAuthority{}, fmt.Errorf("CFSSL generate intermediate CSR: %w", err)
	}
	profile := cfconfig.DefaultConfig()
	profile.Usage = []string{"cert sign", "crl sign"}
	profile.Expiry = intermediateValidity
	profile.ExpiryString = durationString(intermediateValidity)
	profile.Backdate = certificateBackdate
	profile.CAConstraint = cfconfig.CAConstraint{IsCA: true, MaxPathLen: input.PathLength, MaxPathLenZero: input.PathLength == 0}
	profile.CRL = valueOrEmpty(parent.CRLURL)
	profile.OCSP = valueOrEmpty(parent.OCSPURL)
	profile.IssuerURL = []string{s.publicBaseURL + "/issuers/" + parent.Slug + ".cer"}
	policy := &cfconfig.Signing{Default: profile, Profiles: map[string]*cfconfig.SigningProfile{}}
	cfSigner, err := local.NewSigner(parentKey, parentCert, signer.DefaultSigAlgo(parentKey), policy)
	if err != nil {
		return store.CertificateAuthority{}, fmt.Errorf("CFSSL initialize parent signer: %w", err)
	}
	notAfter := minTime(s.now().Add(intermediateValidity), parent.NotAfter)
	certPEM, err := cfSigner.Sign(signer.SignRequest{Request: string(csrPEM), NotBefore: s.now().Add(-certificateBackdate), NotAfter: notAfter})
	if err != nil {
		return store.CertificateAuthority{}, fmt.Errorf("CFSSL sign intermediate CA: %w", err)
	}
	caID, keyID, profileID, err := s.newIDs(ctx)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	chain := append(append([]byte{}, certPEM...), []byte(parent.ChainPEM)...)
	return s.persistCA(ctx, actor, input, "intermediate", &parent.ID, caID, keyID, profileID, certPEM, chain, keyPEM, intermediateValidity)
}

func (s *Service) persistCA(ctx context.Context, actor store.User, input CreateCAInput, kind string, parentID *string, caID, keyID, profileID string, certPEM, chainPEM, keyPEM []byte, validity time.Duration) (store.CertificateAuthority, error) {
	certificate, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	privateKey, err := helpers.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	envelope, err := s.keys.Encrypt(pkcs8, caKeyAAD(caID, 1))
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	publicHash := sha256.Sum256(publicDER)
	subjectJSON, _ := json.Marshal(input.Subject)
	crlURL := s.publicBaseURL + "/crl/" + input.Slug + ".crl"
	ocspURL := s.publicBaseURL + "/ocsp/" + input.Slug
	issuerURL := s.publicBaseURL + "/issuers/" + input.Slug + ".cer"
	ca := store.CertificateAuthority{
		ID: caID, ParentCAID: parentID, Slug: input.Slug, Name: input.Name, Kind: kind,
		Status: "active", Subject: subjectJSON, Serial: certificate.SerialNumber.String(),
		SKI: certificate.SubjectKeyId, AKI: certificate.AuthorityKeyId,
		CertificatePEM: string(certPEM), ChainPEM: string(chainPEM), NotBefore: certificate.NotBefore,
		NotAfter: certificate.NotAfter, PathLength: input.PathLength, CRLURL: &crlURL,
		OCSPURL: &ocspURL, IssuerURL: &issuerURL, CreatedBy: actor.ID,
	}
	algorithm := keyAlgorithm(privateKey)
	key := store.CAKeyVersion{ID: keyID, CAID: caID, Version: 1, Algorithm: algorithm,
		PublicKeyFingerprint: publicHash[:], EncryptedPKCS8: envelope.Ciphertext,
		Nonce: envelope.Nonce, KEKID: envelope.KeyID, Status: "active"}
	profile := store.SigningProfile{ID: profileID, CAID: caID, Name: "default",
		Description: "Default profile", DefaultValidity: leafDefaultValidity,
		MaxValidity: leafMaxValidity, KeyUsages: []string{"signing", "key encipherment"},
		ExtendedKeyUsages: []string{"server auth", "client auth"}, AllowedDNSPatterns: []string{},
		AllowedIPRanges: []string{},
		Policy:          json.RawMessage(`{}`), Enabled: true}
	if kind == "root" {
		profile.DefaultValidity = intermediateValidity
		profile.MaxValidity = intermediateValidity
		profile.KeyUsages = []string{"cert sign", "crl sign"}
		profile.ExtendedKeyUsages = []string{}
	}
	responder, err := s.createOCSPResponder(ctx, caID, certificate, privateKey, input.Subject.CommonName)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	if err := s.store.InsertCA(ctx, ca, key, profile, responder); err != nil {
		return store.CertificateAuthority{}, err
	}
	return s.store.CAByID(ctx, caID)
}

func (s *Service) createOCSPResponder(ctx context.Context, caID string, issuer *x509.Certificate, issuerKey crypto.Signer, commonName string) (store.OCSPResponder, error) {
	responderID, err := s.store.NewID(ctx)
	if err != nil {
		return store.OCSPResponder{}, err
	}
	csrPEM, keyPEM, err := csr.ParseRequest(&csr.CertificateRequest{CN: commonName + " OCSP Responder",
		KeyRequest: &csr.KeyRequest{A: "rsa", S: 3072}})
	if err != nil {
		return store.OCSPResponder{}, fmt.Errorf("generate OCSP responder key: %w", err)
	}
	profile := cfconfig.DefaultConfig()
	profile.Usage = []string{"digital signature", "ocsp signing"}
	profile.Expiry = 365 * 24 * time.Hour
	profile.ExpiryString = durationString(profile.Expiry)
	profile.Backdate = certificateBackdate
	policy := &cfconfig.Signing{Default: profile, Profiles: map[string]*cfconfig.SigningProfile{}}
	cfSigner, err := local.NewSigner(issuerKey, issuer, signer.DefaultSigAlgo(issuerKey), policy)
	if err != nil {
		return store.OCSPResponder{}, fmt.Errorf("initialize OCSP certificate signer: %w", err)
	}
	notBefore := s.now().Add(-certificateBackdate)
	notAfter := minTime(s.now().Add(profile.Expiry), issuer.NotAfter)
	certPEM, err := cfSigner.Sign(signer.SignRequest{Request: string(csrPEM), NotBefore: notBefore, NotAfter: notAfter})
	if err != nil {
		return store.OCSPResponder{}, fmt.Errorf("sign OCSP responder certificate: %w", err)
	}
	responderCert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return store.OCSPResponder{}, err
	}
	responderKey, err := helpers.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return store.OCSPResponder{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(responderKey)
	if err != nil {
		return store.OCSPResponder{}, err
	}
	envelope, err := s.keys.Encrypt(pkcs8, ocspKeyAAD(caID, responderID))
	if err != nil {
		return store.OCSPResponder{}, err
	}
	return store.OCSPResponder{ID: responderID, CAID: caID, CertificatePEM: string(certPEM),
		EncryptedPKCS8: envelope.Ciphertext, Nonce: envelope.Nonce, KEKID: envelope.KeyID,
		NotBefore: responderCert.NotBefore, NotAfter: responderCert.NotAfter, Status: "active"}, nil
}

func (s *Service) CreateRequest(ctx context.Context, actor store.User, input CreateRequestInput) (store.CertificateRequest, error) {
	if actor.Role != "user" && actor.Role != "operator" && actor.Role != "super_admin" {
		return store.CertificateRequest{}, errors.New("invalid requester role")
	}
	ca, err := s.store.CAByID(ctx, input.CAID)
	if err != nil {
		return store.CertificateRequest{}, err
	}
	if ca.Kind != "intermediate" || ca.Status != "active" {
		return store.CertificateRequest{}, errors.New("leaf certificates require an active intermediate CA")
	}
	profile, err := s.profileForRequest(ctx, input.CAID, input.ProfileID)
	if err != nil {
		return store.CertificateRequest{}, err
	}
	if input.RequestedValiditySeconds != nil && (time.Duration(*input.RequestedValiditySeconds)*time.Second > profile.MaxValidity || *input.RequestedValiditySeconds <= 0) {
		return store.CertificateRequest{}, errors.New("requested validity exceeds signing profile")
	}
	mode := "client_csr"
	var csrPEM *string
	subject := input.Subject
	sans := append([]string(nil), input.SANs...)
	if input.ServerGenerateKey {
		mode = "server_generated"
		if input.CSRPEM != "" || strings.TrimSpace(subject.CommonName) == "" {
			return store.CertificateRequest{}, errors.New("server-generated requests require a subject and must not include a CSR")
		}
	} else {
		if input.CSRPEM == "" {
			return store.CertificateRequest{}, errors.New("csr_pem is required unless server_generate_key is true")
		}
		parsed, err := parseAndValidateCSR(input.CSRPEM)
		if err != nil {
			return store.CertificateRequest{}, err
		}
		csrPEM = &input.CSRPEM
		subject = subjectFromPKIX(parsed.Subject)
		sans = csrHosts(parsed)
	}
	if err := validateSANPolicy(sans, profile); err != nil {
		return store.CertificateRequest{}, err
	}
	subjectJSON, _ := json.Marshal(subject)
	sansJSON, _ := json.Marshal(sans)
	return s.store.CreateCertificateRequest(ctx, store.CertificateRequest{
		RequesterID: actor.ID, CAID: input.CAID, ProfileID: profile.ID, CSRPEM: csrPEM,
		RequestedSubject: subjectJSON, RequestedSANs: sansJSON, KeyGenerationMode: mode,
		RequestedValiditySecs: input.RequestedValiditySeconds,
	})
}

func (s *Service) ProcessOne(ctx context.Context, workerID string) (IssueResult, error) {
	jobID, requestID, err := s.store.ClaimIssuanceJob(ctx, workerID)
	if err != nil {
		return IssueResult{}, err
	}
	result, err := s.issue(ctx, jobID, requestID)
	if err != nil {
		_ = s.store.FailIssuance(ctx, jobID, requestID, "issuance_failed", false)
		return IssueResult{}, err
	}
	return result, nil
}

func (s *Service) issue(ctx context.Context, jobID, requestID string) (IssueResult, error) {
	req, err := s.store.RequestByID(ctx, requestID)
	if err != nil {
		return IssueResult{}, err
	}
	ca, err := s.store.CAByID(ctx, req.CAID)
	if err != nil || ca.Status != "active" || ca.Kind != "intermediate" {
		return IssueResult{}, errors.New("issuing CA is unavailable")
	}
	profile, err := s.store.ProfileByID(ctx, req.ProfileID)
	if err != nil || !profile.Enabled {
		return IssueResult{}, errors.New("signing profile is unavailable")
	}
	caCert, caKey, err := s.loadSigner(ctx, ca)
	if err != nil {
		return IssueResult{}, err
	}

	var csrPEM []byte
	var privatePKCS8 []byte
	var subject Subject
	var hosts []string
	_ = json.Unmarshal(req.RequestedSubject, &subject)
	_ = json.Unmarshal(req.RequestedSANs, &hosts)
	if req.KeyGenerationMode == "server_generated" {
		csrPEM, privatePKCS8, err = generateLeafCSR(subject, hosts)
		if err != nil {
			return IssueResult{}, err
		}
	} else {
		csrPEM = []byte(valueOrEmpty(req.CSRPEM))
	}
	if _, err := parseAndValidateCSR(string(csrPEM)); err != nil {
		return IssueResult{}, err
	}
	if err := validateSANPolicy(hosts, profile); err != nil {
		return IssueResult{}, err
	}

	validity := profile.DefaultValidity
	if req.RequestedValiditySecs != nil {
		validity = time.Duration(*req.RequestedValiditySecs) * time.Second
	}
	now := s.now()
	notAfter := minTime(now.Add(validity), ca.NotAfter)
	cfProfile := cfconfig.DefaultConfig()
	cfProfile.Usage = append(append([]string{}, profile.KeyUsages...), profile.ExtendedKeyUsages...)
	cfProfile.Expiry = validity
	cfProfile.ExpiryString = durationString(validity)
	cfProfile.Backdate = certificateBackdate
	cfProfile.CRL = valueOrEmpty(ca.CRLURL)
	cfProfile.OCSP = valueOrEmpty(ca.OCSPURL)
	cfProfile.IssuerURL = []string{valueOrEmpty(ca.IssuerURL)}
	cfProfile.CSRWhitelist = &cfconfig.CSRWhitelist{Subject: true, PublicKeyAlgorithm: true,
		PublicKey: true, SignatureAlgorithm: true, DNSNames: true, IPAddresses: true,
		EmailAddresses: profile.AllowEmailSANs, URIs: profile.AllowURISANs}
	policy := &cfconfig.Signing{Default: cfProfile, Profiles: map[string]*cfconfig.SigningProfile{}}
	cfSigner, err := local.NewSigner(caKey, caCert, signer.DefaultSigAlgo(caKey), policy)
	if err != nil {
		return IssueResult{}, err
	}
	certPEM, err := cfSigner.Sign(signer.SignRequest{Request: string(csrPEM), Hosts: hosts,
		NotBefore: now.Add(-certificateBackdate), NotAfter: notAfter})
	if err != nil {
		return IssueResult{}, fmt.Errorf("CFSSL sign certificate: %w", err)
	}
	parsedCert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return IssueResult{}, err
	}
	certID, err := s.store.NewID(ctx)
	if err != nil {
		return IssueResult{}, err
	}
	fingerprint := sha256.Sum256(parsedCert.Raw)
	subjectJSON, _ := json.Marshal(subjectFromPKIX(parsedCert.Subject))
	sansJSON, _ := json.Marshal(csrHostsFromCertificate(parsedCert))
	certificate := store.Certificate{ID: certID, IssuerCAID: ca.ID, OwnerUserID: req.RequesterID,
		RequestID: &req.ID, Serial: parsedCert.SerialNumber.String(), AKI: parsedCert.AuthorityKeyId,
		SKI: parsedCert.SubjectKeyId, FingerprintSHA256: fingerprint[:],
		CertificatePEM: string(certPEM), ChainPEM: string(certPEM) + ca.ChainPEM,
		Subject: subjectJSON, SANs: sansJSON, NotBefore: parsedCert.NotBefore, NotAfter: parsedCert.NotAfter, Status: "good"}
	var artifact *store.KeyArtifact
	if len(privatePKCS8) > 0 {
		envelope, err := s.keys.Encrypt(privatePKCS8, leafKeyAAD(certID))
		if err != nil {
			return IssueResult{}, err
		}
		_, tokenHash, err := security.NewToken()
		if err != nil {
			return IssueResult{}, err
		}
		artifact = &store.KeyArtifact{EncryptedPKCS8: envelope.Ciphertext, Nonce: envelope.Nonce,
			KEKID: envelope.KeyID, DownloadTokenHash: tokenHash, ExpiresAt: now.Add(24 * time.Hour)}
	}
	if err := s.store.CompleteIssuance(ctx, jobID, certificate, artifact); err != nil {
		return IssueResult{}, err
	}
	return IssueResult{Certificate: certificate}, nil
}

func (s *Service) ExportCAKey(ctx context.Context, caID string) ([]byte, error) {
	ca, err := s.store.CAByID(ctx, caID)
	if err != nil {
		return nil, err
	}
	_, privateKey, err := s.loadSigner(ctx, ca)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func (s *Service) DownloadLeafKey(ctx context.Context, certificateID, ownerUserID string) ([]byte, error) {
	artifact, err := s.store.ConsumeLeafKeyArtifact(ctx, certificateID, ownerUserID, s.now())
	if err != nil {
		return nil, err
	}
	plain, err := s.keys.Decrypt(security.Envelope{KeyID: artifact.KEKID, Nonce: artifact.Nonce,
		Ciphertext: artifact.EncryptedPKCS8}, leafKeyAAD(certificateID))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain}), nil
}

func (s *Service) GenerateCRL(ctx context.Context, caID string) ([]byte, error) {
	ca, err := s.store.CAByID(ctx, caID)
	if err != nil {
		return nil, err
	}
	issuer, key, err := s.loadSigner(ctx, ca)
	if err != nil {
		return nil, err
	}
	revoked, err := s.store.RevokedCertificates(ctx, caID)
	if err != nil {
		return nil, err
	}
	records := make([]certdb.CertificateRecord, 0, len(revoked))
	for _, item := range revoked {
		records = append(records, certdb.CertificateRecord{Serial: item.Serial, RevokedAt: item.RevokedAt, Reason: item.Reason})
	}
	der, err := cfcrl.NewCRLFromDB(records, issuer, key, 7*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("CFSSL generate CRL: %w", err)
	}
	digest := sha256.Sum256(der)
	now := s.now()
	if err := s.store.SaveCRL(ctx, caID, der, digest[:], now, now.Add(7*24*time.Hour)); err != nil {
		return nil, err
	}
	return der, nil
}

func (s *Service) Revoke(ctx context.Context, actor store.User, certificateID string, reason int, comment string) (store.Certificate, error) {
	if reason < 0 || reason > 10 || reason == 7 {
		return store.Certificate{}, errors.New("invalid RFC 5280 revocation reason")
	}
	cert, err := s.store.RevokeCertificate(ctx, certificateID, actor, reason, comment)
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := s.GenerateCRL(ctx, cert.IssuerCAID); err != nil {
		return store.Certificate{}, fmt.Errorf("certificate revoked but CRL regeneration failed: %w", err)
	}
	return cert, nil
}

func (s *Service) OCSPResponse(ctx context.Context, ca store.CertificateAuthority, cert store.Certificate, issuerHash crypto.Hash) ([]byte, error) {
	if issuerHash != crypto.SHA1 && issuerHash != crypto.SHA256 && issuerHash != crypto.SHA384 && issuerHash != crypto.SHA512 {
		return nil, errors.New("unsupported OCSP issuer hash")
	}
	issuer, _, err := s.loadSigner(ctx, ca)
	if err != nil {
		return nil, err
	}
	responderRecord, err := s.store.ActiveOCSPResponder(ctx, ca.ID)
	if err != nil {
		return nil, err
	}
	responder, err := helpers.ParseCertificatePEM([]byte(responderRecord.CertificatePEM))
	if err != nil {
		return nil, err
	}
	plain, err := s.keys.Decrypt(security.Envelope{KeyID: responderRecord.KEKID, Nonce: responderRecord.Nonce,
		Ciphertext: responderRecord.EncryptedPKCS8}, ocspKeyAAD(ca.ID, responderRecord.ID))
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, errors.New("stored OCSP key is not valid PKCS#8")
	}
	key, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("stored OCSP key cannot sign")
	}
	parsed, err := helpers.ParseCertificatePEM([]byte(cert.CertificatePEM))
	if err != nil {
		return nil, err
	}
	status := cert.Status
	reason := 0
	revokedAt := time.Time{}
	if status == "revoked" {
		revocation, err := s.store.RevocationForCertificate(ctx, cert.ID)
		if err != nil {
			return nil, err
		}
		reason = revocation.Reason
		revokedAt = revocation.RevokedAt
	} else {
		status = "good"
	}
	cfSigner, err := cfocsp.NewSigner(issuer, responder, key, 4*time.Hour)
	if err != nil {
		return nil, err
	}
	responseDER, err := cfSigner.Sign(cfocsp.SignRequest{Certificate: parsed, Status: status, Reason: reason,
		RevokedAt: revokedAt, IssuerHash: issuerHash})
	if err != nil {
		return nil, err
	}
	response, err := ocsp.ParseResponse(responseDER, issuer)
	if err != nil {
		return nil, fmt.Errorf("verify generated OCSP response: %w", err)
	}
	var revokedAtValue *time.Time
	if status == "revoked" {
		revokedAtValue = &revokedAt
	}
	if err := s.store.SaveOCSPResponse(ctx, cert.ID, responderRecord.ID, status, reason,
		revokedAtValue, responseDER, response.ProducedAt, response.ThisUpdate, response.NextUpdate); err != nil {
		return nil, err
	}
	return responseDER, nil
}

func ParseOCSPRequest(body []byte) (*ocsp.Request, error) {
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		return nil, errors.New("malformed OCSP request")
	}
	return req, nil
}

func (s *Service) loadSigner(ctx context.Context, ca store.CertificateAuthority) (*x509.Certificate, crypto.Signer, error) {
	certificate, err := helpers.ParseCertificatePEM([]byte(ca.CertificatePEM))
	if err != nil {
		return nil, nil, err
	}
	keyRecord, err := s.store.ActiveCAKey(ctx, ca.ID)
	if err != nil {
		return nil, nil, err
	}
	plain, err := s.keys.Decrypt(security.Envelope{KeyID: keyRecord.KEKID, Nonce: keyRecord.Nonce,
		Ciphertext: keyRecord.EncryptedPKCS8}, caKeyAAD(ca.ID, keyRecord.Version))
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, nil, errors.New("stored CA key is not valid PKCS#8")
	}
	privateKey, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("stored CA key cannot sign")
	}
	return certificate, privateKey, nil
}

func (s *Service) profileForRequest(ctx context.Context, caID, profileID string) (store.SigningProfile, error) {
	if profileID == "" {
		return s.store.DefaultProfileForCA(ctx, caID)
	}
	profile, err := s.store.ProfileByID(ctx, profileID)
	if err == nil && profile.CAID != caID {
		return store.SigningProfile{}, errors.New("signing profile belongs to another CA")
	}
	return profile, err
}

func parseAndValidateCSR(value string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, errors.New("csr_pem must contain exactly one PEM certificate request")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return nil, errors.New("CSR signature is invalid")
	}
	switch key := request.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return nil, errors.New("CSR RSA key must contain at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return nil, errors.New("CSR ECDSA key must use P-256 or P-384")
		}
	default:
		return nil, errors.New("CSR key algorithm is not permitted")
	}
	return request, nil
}

func generateLeafCSR(subject Subject, hosts []string) ([]byte, []byte, error) {
	req := &csr.CertificateRequest{CN: subject.CommonName, Names: []csr.Name{subjectName(subject)},
		Hosts: hosts, KeyRequest: &csr.KeyRequest{A: "rsa", S: 3072}}
	csrPEM, keyPEM, err := csr.ParseRequest(req)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := helpers.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	return csrPEM, pkcs8, err
}

func validateSANPolicy(hosts []string, profile store.SigningProfile) error {
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			if len(profile.AllowedIPRanges) == 0 {
				continue
			}
			allowed := false
			for _, rawNetwork := range profile.AllowedIPRanges {
				_, network, err := net.ParseCIDR(rawNetwork)
				if err == nil && network.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("IP SAN %q is not allowed by the signing profile", host)
			}
			continue
		}
		if address, err := url.ParseRequestURI(host); err == nil && address.Scheme != "" {
			if !profile.AllowURISANs {
				return errors.New("URI SANs are not allowed by the signing profile")
			}
			continue
		}
		if strings.Contains(host, "@") {
			if !profile.AllowEmailSANs {
				return errors.New("email SANs are not allowed by the signing profile")
			}
			continue
		}
		if len(profile.AllowedDNSPatterns) == 0 {
			continue
		}
		allowed := false
		for _, pattern := range profile.AllowedDNSPatterns {
			if matched, _ := path.Match(strings.ToLower(pattern), strings.ToLower(host)); matched {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("DNS SAN %q is not allowed by the signing profile", host)
		}
	}
	return nil
}

func validateCAInput(input CreateCAInput, root bool) error {
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Subject.CommonName) == "" {
		return errors.New("CA name and subject common_name are required")
	}
	if len(input.Slug) < 2 || len(input.Slug) > 63 {
		return errors.New("CA slug must contain 2 to 63 characters")
	}
	for _, r := range input.Slug {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return errors.New("CA slug must contain lowercase letters, digits, or hyphens")
		}
	}
	if root && input.ParentCAID != "" {
		return errors.New("root CA must not have a parent")
	}
	if !root && input.ParentCAID == "" {
		return errors.New("intermediate CA requires parent_ca_id")
	}
	if input.PathLength < 0 || input.PathLength > 5 {
		return errors.New("path_length must be between 0 and 5")
	}
	return nil
}

func (s *Service) newIDs(ctx context.Context) (string, string, string, error) {
	caID, err := s.store.NewID(ctx)
	if err != nil {
		return "", "", "", err
	}
	keyID, err := s.store.NewID(ctx)
	if err != nil {
		return "", "", "", err
	}
	profileID, err := s.store.NewID(ctx)
	return caID, keyID, profileID, err
}

func subjectName(subject Subject) csr.Name {
	return csr.Name{C: subject.Country, ST: subject.Province, L: subject.Locality,
		O: subject.Organization, OU: subject.OrganizationalUnit}
}

func subjectFromPKIX(name pkix.Name) Subject {
	return Subject{
		CommonName:         name.CommonName,
		Country:            first(name.Country),
		Province:           first(name.Province),
		Locality:           first(name.Locality),
		Organization:       first(name.Organization),
		OrganizationalUnit: first(name.OrganizationalUnit),
	}
}

func csrHosts(req *x509.CertificateRequest) []string {
	var out []string
	out = append(out, req.DNSNames...)
	for _, ip := range req.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, req.EmailAddresses...)
	for _, uri := range req.URIs {
		out = append(out, uri.String())
	}
	return out
}

func csrHostsFromCertificate(cert *x509.Certificate) []string {
	var out []string
	out = append(out, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		out = append(out, uri.String())
	}
	return out
}

func caKeyAAD(caID string, version int) []byte {
	return []byte(fmt.Sprintf("ca-key:%s:%d", caID, version))
}
func leafKeyAAD(certificateID string) []byte { return []byte("leaf-key:" + certificateID) }
func ocspKeyAAD(caID, responderID string) []byte {
	return []byte("ocsp-key:" + caID + ":" + responderID)
}

func keyAlgorithm(key crypto.Signer) string {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			return "ECDSA-P256"
		case elliptic.P384():
			return "ECDSA-P384"
		}
	}
	return "unknown"
}

func durationString(value time.Duration) string { return fmt.Sprintf("%dh", int64(value.Hours())) }
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
