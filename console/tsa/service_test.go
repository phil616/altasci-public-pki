package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	dtimestamp "github.com/digitorus/timestamp"
)

var testNow = time.Now().UTC().Truncate(time.Microsecond)

type fixedTimeSource struct {
	moment Moment
	err    error
}

func (source fixedTimeSource) Now(context.Context) (Moment, error) {
	return source.moment, source.err
}

type fakeRepository struct {
	ca               store.CertificateAuthority
	caKey            store.CAKeyVersion
	authority        store.TimestampAuthority
	tokens           []store.TimestampToken
	saveCalls        int
	serialCollisions int
	saveErr          error
}

func (repository *fakeRepository) NewID(context.Context) (string, error) {
	return "00000000-0000-7000-8000-000000000001", nil
}

func (repository *fakeRepository) CAByID(_ context.Context, id string) (store.CertificateAuthority, error) {
	if id != repository.ca.ID {
		return store.CertificateAuthority{}, store.ErrNotFound
	}
	return repository.ca, nil
}

func (repository *fakeRepository) ActiveCAKey(_ context.Context, caID string) (store.CAKeyVersion, error) {
	if caID != repository.caKey.CAID {
		return store.CAKeyVersion{}, store.ErrNotFound
	}
	return repository.caKey, nil
}

func (repository *fakeRepository) InsertTimestampAuthority(_ context.Context, authority store.TimestampAuthority) (store.TimestampAuthority, error) {
	authority.CreatedAt = testNow
	repository.authority = authority
	return authority, nil
}

func (repository *fakeRepository) TimestampAuthorityBySlug(_ context.Context, slug string) (store.TimestampAuthority, error) {
	if repository.authority.Slug != slug {
		return store.TimestampAuthority{}, store.ErrNotFound
	}
	return repository.authority, nil
}

func (repository *fakeRepository) ListTimestampAuthorities(_ context.Context, caID string) ([]store.TimestampAuthority, error) {
	if repository.authority.CAID == caID {
		return []store.TimestampAuthority{repository.authority}, nil
	}
	return nil, nil
}

func (repository *fakeRepository) SaveTimestampToken(_ context.Context, token store.TimestampToken) error {
	repository.saveCalls++
	if repository.serialCollisions > 0 {
		repository.serialCollisions--
		return store.ErrTimestampSerialCollision
	}
	if repository.saveErr != nil {
		return repository.saveErr
	}
	for _, existing := range repository.tokens {
		if existing.TSAID == token.TSAID && existing.Serial == token.Serial {
			return store.ErrTimestampSerialCollision
		}
	}
	repository.tokens = append(repository.tokens, token)
	return nil
}

func TestRFC3161Lifecycle(t *testing.T) {
	service, repository, issuerPEM := newTestService(t)
	actor := store.User{ID: "00000000-0000-7000-8000-000000000099", Role: "super_admin"}
	authority, err := service.CreateAuthority(context.Background(), actor, CreateAuthorityInput{
		CAID: repository.ca.ID, Slug: "release-tsa", Name: "Release Time-Stamping Unit",
		PolicyOID: "2.25.82903600839381497744334944801749237370",
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate := parseCertificate(t, authority.CertificatePEM)
	if err := validateTSUCertificate(certificate); err != nil {
		t.Fatal(err)
	}
	if certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("unexpected TSU key usage: %v", certificate.KeyUsage)
	}
	criticalEKU := false
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(extendedKeyUsageOID) {
			criticalEKU = extension.Critical
		}
	}
	if !criticalEKU {
		t.Fatal("TSU timestamping EKU is not critical")
	}

	policy, _ := parseOID(authority.PolicyOID)
	nonce := big.NewInt(987654321)
	requestDER, err := dtimestamp.CreateRequest(bytes.NewReader([]byte("release artifact")), &dtimestamp.RequestOptions{
		Hash: crypto.SHA256, Certificates: true, TSAPolicy: policy, Nonce: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	responseDER, err := service.Respond(context.Background(), authority.Slug, requestDER)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := dtimestamp.ParseResponse(responseDER)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.PolicyOID.Equal(policy) || parsed.Nonce == nil || parsed.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("response policy or nonce mismatch: policy=%s nonce=%v", parsed.PolicyOID, parsed.Nonce)
	}
	if parsed.HashAlgorithm != crypto.SHA256 || !parsed.Time.Equal(testNow.Truncate(time.Second)) || parsed.Accuracy != 1500*time.Millisecond {
		t.Fatalf("unexpected timestamp fields: hash=%v time=%s accuracy=%s", parsed.HashAlgorithm, parsed.Time, parsed.Accuracy)
	}
	if len(parsed.Certificates) < 1 || len(repository.tokens) != 1 {
		t.Fatalf("certificate/token ledger missing: certificates=%d tokens=%d", len(parsed.Certificates), len(repository.tokens))
	}
	if repository.tokens[0].Serial != parsed.SerialNumber.String() || !bytes.Equal(repository.tokens[0].TokenDER, responseDER) {
		t.Fatal("persisted timestamp token does not match the returned response")
	}

	secondResponse, err := service.Respond(context.Background(), authority.Slug, requestDER)
	if err != nil {
		t.Fatal(err)
	}
	second, err := dtimestamp.ParseResponse(secondResponse)
	if err != nil {
		t.Fatal(err)
	}
	if second.SerialNumber.Cmp(parsed.SerialNumber) == 0 || len(repository.tokens) != 2 {
		t.Fatal("repeated requests must receive independently serialised tokens")
	}

	withoutCertificate, err := dtimestamp.CreateRequest(bytes.NewReader([]byte("without certificate")), &dtimestamp.RequestOptions{Hash: crypto.SHA384})
	if err != nil {
		t.Fatal(err)
	}
	responseWithoutCertificate, err := service.Respond(context.Background(), authority.Slug, withoutCertificate)
	if err != nil {
		t.Fatal(err)
	}
	parsedWithoutCertificate, err := dtimestamp.ParseResponse(responseWithoutCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedWithoutCertificate.Certificates) != 0 || parsedWithoutCertificate.HashAlgorithm != crypto.SHA384 {
		t.Fatalf("certReq=false was not honored: certificates=%d hash=%v", len(parsedWithoutCertificate.Certificates), parsedWithoutCertificate.HashAlgorithm)
	}

	verifyWithOpenSSL(t, issuerPEM, requestDER, responseDER)
}

func TestRFC3161RejectionsAndPersistenceFailure(t *testing.T) {
	service, repository, _ := newTestService(t)
	actor := store.User{ID: "00000000-0000-7000-8000-000000000099", Role: "super_admin"}
	authority, err := service.CreateAuthority(context.Background(), actor, CreateAuthorityInput{
		CAID: repository.ca.ID, Slug: "test-tsa", Name: "Test TSU", PolicyOID: "1.3.6.1.4.1.55555.1.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	sha1Request, _ := dtimestamp.CreateRequest(bytes.NewReader([]byte("sha1")), &dtimestamp.RequestOptions{Hash: crypto.SHA1})
	assertRejected(t, service, authority.Slug, sha1Request, "unsupported Algorithm Identifier")

	wrongPolicyRequest, _ := dtimestamp.CreateRequest(bytes.NewReader([]byte("policy")), &dtimestamp.RequestOptions{
		Hash: crypto.SHA256, TSAPolicyOID: asn1.ObjectIdentifier{1, 2, 3, 4},
	})
	assertRejected(t, service, authority.Slug, wrongPolicyRequest, "policy")

	badDigestRequest, _ := (&dtimestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: []byte{1, 2, 3}}).Marshal()
	assertRejected(t, service, authority.Slug, badDigestRequest, "wrong format")

	extensionRequest, _ := (&dtimestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: make([]byte, 32),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{5, 0}}}}).Marshal()
	assertRejected(t, service, authority.Slug, extensionRequest, "extension")

	validRequest, _ := dtimestamp.CreateRequest(bytes.NewReader([]byte("version")), &dtimestamp.RequestOptions{Hash: crypto.SHA256})
	versionTwo := append([]byte(nil), validRequest...)
	marker := bytes.Index(versionTwo, []byte{2, 1, 1})
	if marker < 0 {
		t.Fatal("request version marker not found")
	}
	versionTwo[marker+2] = 2
	assertRejected(t, service, authority.Slug, versionTwo, "wrong format")

	repository.serialCollisions = 1
	responseDER, err := service.Respond(context.Background(), authority.Slug, validRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dtimestamp.ParseResponse(responseDER); err != nil || repository.saveCalls != 2 {
		t.Fatalf("serial collision was not retried: calls=%d err=%v", repository.saveCalls, err)
	}

	repository.saveErr = errors.New("database unavailable")
	responseDER, err = service.Respond(context.Background(), authority.Slug, validRequest)
	if err == nil || !strings.Contains(err.Error(), "persist timestamp token") {
		t.Fatalf("expected persistence error, got %v", err)
	}
	if _, parseErr := dtimestamp.ParseResponse(responseDER); parseErr == nil || !strings.Contains(parseErr.Error(), "system failure") {
		t.Fatalf("expected RFC systemFailure response, got %v", parseErr)
	}

	service.clock = fixedTimeSource{err: errors.New("NTP unsynchronized")}
	responseDER, err = service.Respond(context.Background(), authority.Slug, validRequest)
	if err == nil || !strings.Contains(err.Error(), "NTP unsynchronized") {
		t.Fatalf("expected time source error, got %v", err)
	}
	if _, parseErr := dtimestamp.ParseResponse(responseDER); parseErr == nil || !strings.Contains(parseErr.Error(), "time source is not available") {
		t.Fatalf("expected RFC timeNotAvailable response, got %v", parseErr)
	}
}

func TestSystemTimeSourceRejectsInvalidUncertainty(t *testing.T) {
	_, err := NewSystemTimeSource(0, false).Now(context.Background())
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Fatalf("expected invalid uncertainty error, got %v", err)
	}
}

func newTestService(t *testing.T) (*Service, *fakeRepository, []byte) {
	t.Helper()
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
		IsCA: true, SubjectKeyId: bytes.Repeat([]byte{1}, 20), MaxPathLen: 0, MaxPathLenZero: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	pkcs8, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	masterKey := bytes.Repeat([]byte{42}, 32)
	keyring := security.Keyring{ActiveID: "v1", Keys: map[string][]byte{"v1": masterKey}}
	envelope, err := keyring.Encrypt(pkcs8, caKeyAAD("ca-1", 1))
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		ca: store.CertificateAuthority{ID: "ca-1", Kind: "intermediate", Status: "active",
			CertificatePEM: string(issuerPEM), ChainPEM: string(issuerPEM), NotAfter: issuerTemplate.NotAfter},
		caKey: store.CAKeyVersion{ID: "key-1", CAID: "ca-1", Version: 1, Algorithm: "RSA-2048",
			EncryptedPKCS8: envelope.Ciphertext, Nonce: envelope.Nonce, KEKID: envelope.KeyID, Status: "active"},
	}
	service, err := NewService(repository, keyring, fixedTimeSource{moment: Moment{Time: testNow, Accuracy: 1500 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	return service, repository, issuerPEM
}

func parseCertificate(t *testing.T, value string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		t.Fatal("certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func assertRejected(t *testing.T, service *Service, slug string, requestDER []byte, contains string) {
	t.Helper()
	responseDER, internalErr := service.Respond(context.Background(), slug, requestDER)
	if internalErr != nil {
		t.Fatalf("unexpected internal error: %v", internalErr)
	}
	_, err := dtimestamp.ParseResponse(responseDER)
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected rejection containing %q, got %v", contains, err)
	}
}

func verifyWithOpenSSL(t *testing.T, issuerPEM, requestDER, responseDER []byte) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is not installed")
	}
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.tsq")
	responsePath := filepath.Join(directory, "response.tsr")
	issuerPath := filepath.Join(directory, "issuer.pem")
	for path, value := range map[string][]byte{requestPath: requestDER, responsePath: responseDER, issuerPath: issuerPEM} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	parse := exec.Command(openssl, "ts", "-reply", "-in", responsePath, "-text")
	if output, err := parse.CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL could not parse timestamp response: %v\n%s", err, output)
	}
	verify := exec.Command(openssl, "ts", "-verify", "-queryfile", requestPath, "-in", responsePath, "-CAfile", issuerPath)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL could not verify timestamp response: %v\n%s", err, output)
	}
}
