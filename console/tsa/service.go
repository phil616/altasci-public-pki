// Package tsa implements an RFC 3161/RFC 5816 Time-Stamping Authority.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/helpers"
	dtimestamp "github.com/digitorus/timestamp"
)

const (
	defaultValidity = 2 * 365 * 24 * time.Hour
	minimumValidity = 24 * time.Hour
	maximumValidity = 3 * 365 * 24 * time.Hour
	backdate        = 5 * time.Minute
	serialRetries   = 3
)

var (
	timestampingEKUOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	extendedKeyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 37}
)

type repository interface {
	NewID(context.Context) (string, error)
	CAByID(context.Context, string) (store.CertificateAuthority, error)
	ActiveCAKey(context.Context, string) (store.CAKeyVersion, error)
	InsertTimestampAuthority(context.Context, store.TimestampAuthority) (store.TimestampAuthority, error)
	TimestampAuthorityBySlug(context.Context, string) (store.TimestampAuthority, error)
	ListTimestampAuthorities(context.Context, string) ([]store.TimestampAuthority, error)
	SaveTimestampToken(context.Context, store.TimestampToken) error
}

type Service struct {
	store repository
	keys  security.Keyring
	clock TimeSource
}

type CreateAuthorityInput struct {
	CAID            string `json:"-"`
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	PolicyOID       string `json:"policy_oid"`
	ValiditySeconds *int64 `json:"validity_seconds,omitempty"`
}

func NewService(data repository, keys security.Keyring, clock TimeSource) (*Service, error) {
	if data == nil || clock == nil {
		return nil, errors.New("TSA store and time source are required")
	}
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	return &Service{store: data, keys: keys, clock: clock}, nil
}

func (s *Service) ListAuthorities(ctx context.Context, caID string) ([]store.TimestampAuthority, error) {
	return s.store.ListTimestampAuthorities(ctx, caID)
}

// CreateAuthority creates a dedicated TSU key and an end-entity certificate
// whose only EKU is the critical id-kp-timeStamping extension required by
// RFC 3161 section 2.3.
func (s *Service) CreateAuthority(ctx context.Context, actor store.User, input CreateAuthorityInput) (store.TimestampAuthority, error) {
	if actor.Role != "super_admin" {
		return store.TimestampAuthority{}, errors.New("only the super administrator may create timestamp authorities")
	}
	if err := validateCreateInput(input); err != nil {
		return store.TimestampAuthority{}, err
	}
	policyOID, err := parseOID(input.PolicyOID)
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	issuerRecord, err := s.store.CAByID(ctx, input.CAID)
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	if issuerRecord.Kind != "intermediate" || issuerRecord.Status != "active" {
		return store.TimestampAuthority{}, errors.New("timestamp authorities require an active intermediate CA")
	}
	issuer, issuerKey, err := s.loadCA(ctx, issuerRecord)
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	moment, err := s.clock.Now(ctx)
	if err != nil {
		return store.TimestampAuthority{}, fmt.Errorf("time source unavailable: %w", err)
	}
	validity := defaultValidity
	if input.ValiditySeconds != nil {
		validity = time.Duration(*input.ValiditySeconds) * time.Second
	}
	notBefore := moment.Time.Add(-backdate)
	notAfter := moment.Time.Add(validity)
	chainExpiry, err := security.ChainNotAfter([]byte(issuerRecord.ChainPEM))
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	if chainExpiry.Before(notAfter) {
		notAfter = chainExpiry
	}
	if !notAfter.After(moment.Time.Add(minimumValidity)) {
		return store.TimestampAuthority{}, errors.New("issuer CA expires too soon for a timestamp authority")
	}

	authorityID, err := s.store.NewID(ctx)
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return store.TimestampAuthority{}, fmt.Errorf("generate TSU key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	ski := sha256.Sum256(publicDER)
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{timestampingEKUOID})
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: strings.TrimSpace(input.Name)},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          ski[:20],
		AuthorityKeyId:        issuer.SubjectKeyId,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       []pkix.Extension{{Id: extendedKeyUsageOID, Critical: true, Value: ekuValue}},
	}
	if issuerRecord.OCSPURL != nil {
		template.OCSPServer = []string{*issuerRecord.OCSPURL}
	}
	if issuerRecord.CRLURL != nil {
		template.CRLDistributionPoints = []string{*issuerRecord.CRLURL}
	}
	if issuerRecord.IssuerURL != nil {
		template.IssuingCertificateURL = []string{*issuerRecord.IssuerURL}
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &privateKey.PublicKey, issuerKey)
	if err != nil {
		return store.TimestampAuthority{}, fmt.Errorf("sign TSU certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	if err := validateTSUCertificate(certificate); err != nil {
		return store.TimestampAuthority{}, fmt.Errorf("generated TSU certificate is invalid: %w", err)
	}
	if err := certificate.CheckSignatureFrom(issuer); err != nil {
		return store.TimestampAuthority{}, fmt.Errorf("verify TSU certificate chain: %w", err)
	}
	if err := security.VerifyIssuedCertificate(certificate, []byte(issuerRecord.ChainPEM), moment.Time); err != nil {
		return store.TimestampAuthority{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	envelope, err := s.keys.Encrypt(pkcs8, timestampKeyAAD(authorityID))
	if err != nil {
		return store.TimestampAuthority{}, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	authority := store.TimestampAuthority{
		ID: authorityID, CAID: issuerRecord.ID, Slug: input.Slug, Name: strings.TrimSpace(input.Name),
		PolicyOID: policyOID.String(), CertificatePEM: string(certificatePEM),
		ChainPEM:       string(append(append([]byte{}, certificatePEM...), []byte(issuerRecord.ChainPEM)...)),
		EncryptedPKCS8: envelope.Ciphertext, Nonce: envelope.Nonce, KEKID: envelope.KeyID,
		AllowedHashes: []string{"SHA-256", "SHA-384", "SHA-512"}, NotBefore: certificate.NotBefore,
		NotAfter: certificate.NotAfter, Status: "active", CreatedBy: actor.ID,
	}
	return s.store.InsertTimestampAuthority(ctx, authority)
}

// Respond parses a TimeStampReq and returns a DER TimeStampResp. Protocol
// failures are returned as a normal RFC 3161 rejection. Internal failures also
// return a valid rejection body plus an error for server-side logging.
func (s *Service) Respond(ctx context.Context, slug string, requestDER []byte) ([]byte, error) {
	version, err := requestVersion(requestDER)
	if err != nil || version != 1 {
		return rejection(dtimestamp.BadDataFormat), nil
	}
	request, err := dtimestamp.ParseRequest(requestDER)
	if err != nil {
		if strings.Contains(err.Error(), "unknown hash function") {
			return rejection(dtimestamp.BadAlgorithm), nil
		}
		return rejection(dtimestamp.BadDataFormat), nil
	}
	if request.HashAlgorithm != crypto.SHA256 && request.HashAlgorithm != crypto.SHA384 && request.HashAlgorithm != crypto.SHA512 {
		return rejection(dtimestamp.BadAlgorithm), nil
	}
	if len(request.HashedMessage) != request.HashAlgorithm.Size() {
		return rejection(dtimestamp.BadDataFormat), nil
	}
	if len(request.Extensions) != 0 {
		return rejection(dtimestamp.UnacceptedExtension), nil
	}
	authority, err := s.store.TimestampAuthorityBySlug(ctx, slug)
	if err != nil {
		return rejectionWithError(dtimestamp.SystemFailure, fmt.Errorf("active timestamp authority %q unavailable: %w", slug, err))
	}
	if authority.Status != "active" {
		return rejectionWithError(dtimestamp.SystemFailure, fmt.Errorf("timestamp authority %q is %s", slug, authority.Status))
	}
	policyOID, err := parseOID(authority.PolicyOID)
	if err != nil {
		return rejectionWithError(dtimestamp.SystemFailure, fmt.Errorf("stored TSA policy OID is invalid: %w", err))
	}
	if request.TSAPolicy.String() != "" && !request.TSAPolicy.Equal(policyOID) {
		return rejection(dtimestamp.UnacceptedPolicy), nil
	}
	hashName := request.HashAlgorithm.String()
	if !contains(authority.AllowedHashes, hashName) {
		return rejection(dtimestamp.BadAlgorithm), nil
	}
	moment, err := s.clock.Now(ctx)
	if err != nil {
		return rejectionWithError(dtimestamp.TimeNotAvailable, err)
	}
	if moment.Time.Before(authority.NotBefore) || !moment.Time.Before(authority.NotAfter) {
		return rejectionWithError(dtimestamp.SystemFailure, errors.New("timestamp authority certificate is outside its validity period"))
	}
	certificate, signer, parents, err := s.loadTimestampSigner(authority)
	if err != nil {
		return rejectionWithError(dtimestamp.SystemFailure, err)
	}
	var parentPEM []byte
	for _, parent := range parents {
		parentPEM = append(parentPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parent.Raw})...)
	}
	if err := security.VerifyIssuedCertificate(certificate, parentPEM, moment.Time); err != nil {
		return rejectionWithError(dtimestamp.SystemFailure, err)
	}

	for attempt := 0; attempt < serialRetries; attempt++ {
		stamp := &dtimestamp.Timestamp{
			HashAlgorithm: request.HashAlgorithm,
			HashedMessage: append([]byte(nil), request.HashedMessage...),
			Time:          moment.Time.UTC().Truncate(time.Microsecond), Accuracy: moment.Accuracy,
			PolicyOID: policyOID, Nonce: request.Nonce, Ordering: false,
			AddTSACertificate: request.Certificates, Certificates: parents,
		}
		responseDER, err := stamp.CreateResponseWithOpts(certificate, signer, crypto.SHA256)
		if err != nil {
			return rejectionWithError(dtimestamp.SystemFailure, fmt.Errorf("sign timestamp response: %w", err))
		}
		parsed, err := dtimestamp.ParseResponse(responseDER)
		if err != nil || parsed.SerialNumber == nil || parsed.SerialNumber.Sign() <= 0 {
			return rejectionWithError(dtimestamp.SystemFailure, fmt.Errorf("validate generated timestamp response: %w", err))
		}
		digest := sha256.Sum256(responseDER)
		var nonce *string
		if request.Nonce != nil {
			value := request.Nonce.String()
			nonce = &value
		}
		err = s.store.SaveTimestampToken(ctx, store.TimestampToken{
			TSAID: authority.ID, Serial: parsed.SerialNumber.String(), HashAlgorithm: hashName,
			MessageImprint: append([]byte(nil), request.HashedMessage...), PolicyOID: policyOID.String(),
			Nonce: nonce, GeneratedAt: parsed.Time, AccuracyMicros: parsed.Accuracy.Microseconds(),
			TokenSHA256: digest[:], TokenDER: responseDER,
		})
		if err == nil {
			return responseDER, nil
		}
		if !errors.Is(err, store.ErrTimestampSerialCollision) {
			return rejectionWithError(dtimestamp.SystemFailure, fmt.Errorf("persist timestamp token: %w", err))
		}
	}
	return rejectionWithError(dtimestamp.SystemFailure, errors.New("could not allocate a unique timestamp serial"))
}

func (s *Service) loadCA(ctx context.Context, authority store.CertificateAuthority) (*x509.Certificate, crypto.Signer, error) {
	certificate, err := helpers.ParseCertificatePEM([]byte(authority.CertificatePEM))
	if err != nil {
		return nil, nil, err
	}
	keyRecord, err := s.store.ActiveCAKey(ctx, authority.ID)
	if err != nil {
		return nil, nil, err
	}
	plain, err := s.keys.Decrypt(security.Envelope{KeyID: keyRecord.KEKID, Nonce: keyRecord.Nonce,
		Ciphertext: keyRecord.EncryptedPKCS8}, caKeyAAD(authority.ID, keyRecord.Version))
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, nil, errors.New("stored CA key is not valid PKCS#8")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("stored CA key cannot sign")
	}
	return certificate, signer, nil
}

func (s *Service) loadTimestampSigner(authority store.TimestampAuthority) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	certificate, err := helpers.ParseCertificatePEM([]byte(authority.CertificatePEM))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validateTSUCertificate(certificate); err != nil {
		return nil, nil, nil, err
	}
	plain, err := s.keys.Decrypt(security.Envelope{KeyID: authority.KEKID, Nonce: authority.Nonce,
		Ciphertext: authority.EncryptedPKCS8}, timestampKeyAAD(authority.ID))
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, nil, nil, errors.New("stored TSU key is not valid PKCS#8")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("stored TSU key cannot sign")
	}
	storedPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(storedPublic, certificate.RawSubjectPublicKeyInfo) {
		return nil, nil, nil, errors.New("stored TSU key does not match its certificate")
	}
	chain, err := parseCertificateChain([]byte(authority.ChainPEM))
	if err != nil || len(chain) < 2 || !bytes.Equal(chain[0].Raw, certificate.Raw) {
		return nil, nil, nil, errors.New("stored TSU certificate chain is invalid")
	}
	if err := certificate.CheckSignatureFrom(chain[1]); err != nil {
		return nil, nil, nil, errors.New("stored TSU certificate is not signed by its recorded issuer")
	}
	return certificate, signer, chain[1:], nil
}

func validateTSUCertificate(certificate *x509.Certificate) error {
	if certificate.IsCA || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("TSU certificate must be an end-entity digital-signature certificate")
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(certificate.UnknownExtKeyUsage) != 0 {
		return errors.New("TSU certificate must contain only id-kp-timeStamping extended key usage")
	}
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(extendedKeyUsageOID) {
			if !extension.Critical {
				return errors.New("TSU extended key usage must be critical")
			}
			return nil
		}
	}
	return errors.New("TSU certificate has no extended key usage extension")
}

func parseCertificateChain(value []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(value) != 0 {
		block, rest := pem.Decode(value)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("certificate chain contains invalid PEM data")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		value = rest
	}
	return certificates, nil
}

func validateCreateInput(input CreateAuthorityInput) error {
	name := strings.TrimSpace(input.Name)
	if name == "" || input.CAID == "" {
		return errors.New("CA and timestamp authority name are required")
	}
	if len(name) > 128 {
		return errors.New("timestamp authority name must not exceed 128 bytes")
	}
	if len(input.Slug) < 2 || len(input.Slug) > 63 {
		return errors.New("timestamp authority slug must contain 2 to 63 characters")
	}
	for _, character := range input.Slug {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return errors.New("timestamp authority slug must contain lowercase letters, digits, or hyphens")
		}
	}
	if _, err := parseOID(input.PolicyOID); err != nil {
		return err
	}
	if input.ValiditySeconds != nil {
		if *input.ValiditySeconds < int64(minimumValidity/time.Second) ||
			*input.ValiditySeconds > int64(maximumValidity/time.Second) {
			return errors.New("timestamp authority validity must be between one day and three years")
		}
	}
	return nil
}

func parseOID(value string) (x509.OID, error) {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		return x509.OID{}, errors.New("policy_oid must be a dotted object identifier")
	}
	oid, err := x509.ParseOID(value)
	if err != nil {
		return x509.OID{}, errors.New("policy_oid contains an invalid arc")
	}
	if oid.String() != value {
		return x509.OID{}, errors.New("policy_oid must use canonical decimal arcs")
	}
	return oid, nil
}

func requestVersion(der []byte) (int, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(der, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return 0, errors.New("malformed TimeStampReq")
	}
	var version int
	if _, err := asn1.Unmarshal(sequence.Bytes, &version); err != nil {
		return 0, errors.New("malformed TimeStampReq version")
	}
	return version, nil
}

func rejection(failure dtimestamp.FailureInfo) []byte {
	response, _ := dtimestamp.CreateErrorResponse(dtimestamp.Rejection, failure)
	return response
}

func rejectionWithError(failure dtimestamp.FailureInfo, err error) ([]byte, error) {
	return rejection(failure), err
}

func randomSerial() (*big.Int, error) {
	value := make([]byte, 20)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	value[0] &= 0x7f
	if bytes.Equal(value, make([]byte, len(value))) {
		value[len(value)-1] = 1
	}
	return new(big.Int).SetBytes(value), nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func caKeyAAD(caID string, version int) []byte {
	return []byte(fmt.Sprintf("ca-key:%s:%d", caID, version))
}

func timestampKeyAAD(authorityID string) []byte {
	return []byte("timestamp-key:" + authorityID)
}
