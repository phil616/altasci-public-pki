package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/console/store"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrInvalidCAImport = errors.New("invalid CA import")
var ErrCAConflict = errors.New("CA certificate or slug already exists")

type ImportCAInput struct {
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Kind           string `json:"kind"`
	ParentCAID     string `json:"parent_ca_id,omitempty"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
}

// ImportCA preserves the original certificate and imports its matching signing
// key into the same encrypted, transactional storage used for generated CAs.
func (s *Service) ImportCA(ctx context.Context, actor store.User, input ImportCAInput) (store.CertificateAuthority, error) {
	if actor.Role != "super_admin" {
		return store.CertificateAuthority{}, errors.New("only the super administrator may import CAs")
	}
	certificate, key, err := validateCAImport(input, s.now())
	if err != nil {
		return store.CertificateAuthority{}, fmt.Errorf("%w: %v", ErrInvalidCAImport, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	chainPEM := certPEM
	var parentID *string
	if input.Kind == "intermediate" {
		parent, err := s.store.CAByID(ctx, input.ParentCAID)
		if errors.Is(err, store.ErrNotFound) {
			return store.CertificateAuthority{}, fmt.Errorf("%w: parent CA was not found", ErrInvalidCAImport)
		}
		if err != nil {
			return store.CertificateAuthority{}, err
		}
		if parent.Status != "active" {
			return store.CertificateAuthority{}, fmt.Errorf("%w: parent CA must be active", ErrInvalidCAImport)
		}
		if err := validateImportedChain(certificate, []byte(parent.ChainPEM), s.now()); err != nil {
			return store.CertificateAuthority{}, fmt.Errorf("%w: %v", ErrInvalidCAImport, err)
		}
		parentID = &parent.ID
		chainPEM = append(append([]byte{}, certPEM...), []byte(parent.ChainPEM)...)
	}
	caID, keyID, profileID, err := s.newIDs(ctx)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return store.CertificateAuthority{}, err
	}
	depth := certificate.MaxPathLen
	if depth == 0 && !certificate.MaxPathLenZero {
		depth = -1
	}
	metadata := CreateCAInput{Name: strings.TrimSpace(input.Name), Slug: input.Slug,
		Subject: subjectFromPKIX(certificate.Subject), PathLength: depth}
	ca, err := s.persistCA(ctx, actor, metadata, input.Kind, parentID, caID, keyID, profileID,
		certPEM, chainPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), certificate.NotAfter.Sub(s.now()))
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "23505" {
		return store.CertificateAuthority{}, ErrCAConflict
	}
	return ca, err
}

func validateCAImport(input ImportCAInput, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	if err := validateCAIdentity(input.Name, input.Slug); err != nil {
		return nil, nil, err
	}
	if input.Kind != "root" && input.Kind != "intermediate" {
		return nil, nil, errors.New("kind must be root or intermediate")
	}
	if (input.Kind == "root" && input.ParentCAID != "") || (input.Kind == "intermediate" && input.ParentCAID == "") {
		return nil, nil, errors.New("only an intermediate CA requires parent_ca_id")
	}
	if input.Kind == "intermediate" {
		var parentID pgtype.UUID
		if err := parentID.Scan(input.ParentCAID); err != nil {
			return nil, nil, errors.New("parent_ca_id must be a valid UUID")
		}
	}
	block, rest := pem.Decode([]byte(strings.TrimSpace(input.CertificatePEM)))
	if !strings.HasPrefix(strings.TrimSpace(input.CertificatePEM), "-----BEGIN CERTIFICATE-----") || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("certificate_pem must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, errors.New("certificate_pem is not a valid X.509 certificate")
	}
	if err := validateImportedCertificate(certificate, now); err != nil {
		return nil, nil, err
	}
	keyBlock, keyRest := pem.Decode([]byte(strings.TrimSpace(input.PrivateKeyPEM)))
	if !strings.HasPrefix(strings.TrimSpace(input.PrivateKeyPEM), "-----BEGIN ") || keyBlock == nil || len(keyBlock.Headers) != 0 || len(bytes.TrimSpace(keyRest)) != 0 ||
		(keyBlock.Type != "PRIVATE KEY" && keyBlock.Type != "RSA PRIVATE KEY" && keyBlock.Type != "EC PRIVATE KEY") {
		return nil, nil, errors.New("private_key_pem must contain one unencrypted PKCS#8, PKCS#1 or SEC1 PEM private key")
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(block), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, nil, errors.New("private key is invalid or does not match the CA certificate")
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("private key cannot sign")
	}
	switch keyAlgorithm(key) {
	case "RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384":
	default:
		return nil, nil, errors.New("CA key must be RSA-2048/3072/4096 or ECDSA-P256/P384")
	}
	if input.Kind == "root" {
		if !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) || certificate.CheckSignatureFrom(certificate) != nil {
			return nil, nil, errors.New("root CA must have a valid self-signature")
		}
		roots := x509.NewCertPool()
		roots.AddCert(certificate)
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return nil, nil, fmt.Errorf("root CA verification failed: %w", err)
		}
	}
	return certificate, key, nil
}

func validateImportedCertificate(certificate *x509.Certificate, now time.Time) error {
	if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("certificate must be a CA with certificate-signing and CRL-signing usages")
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("CA certificate is expired or not yet valid")
	}
	if len(certificate.SubjectKeyId) == 0 {
		return errors.New("CA certificate must contain a Subject Key Identifier for CRL publication")
	}
	if certificate.SerialNumber.Sign() <= 0 || len(certificate.SerialNumber.String()) > 50 {
		return errors.New("CA serial must be positive and contain at most 50 decimal digits")
	}
	if len(certificate.UnhandledCriticalExtensions) != 0 {
		return errors.New("CA certificate has unsupported critical extensions")
	}
	return nil
}

func validateImportedChain(certificate *x509.Certificate, parentPEM []byte, now time.Time) error {
	chain := []*x509.Certificate{certificate}
	for len(bytes.TrimSpace(parentPEM)) != 0 {
		block, rest := pem.Decode(parentPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("parent CA chain is invalid")
		}
		parent, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("parent CA chain is invalid")
		}
		chain, parentPEM = append(chain, parent), rest
	}
	if len(chain) < 2 {
		return errors.New("parent CA chain is empty")
	}
	nonSelfIssued := 0
	for i, parent := range chain[1:] {
		child := chain[i]
		if err := validateImportedCertificate(parent, now); err != nil {
			return fmt.Errorf("parent CA: %w", err)
		}
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) || child.CheckSignatureFrom(parent) != nil ||
			(len(child.AuthorityKeyId) > 0 && !bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId)) {
			return errors.New("certificate was not issued by the selected parent chain")
		}
		if !bytes.Equal(child.RawIssuer, child.RawSubject) {
			nonSelfIssued++
		}
		if (parent.MaxPathLen > 0 || parent.MaxPathLenZero) && nonSelfIssued > parent.MaxPathLen {
			return errors.New("import exceeds a parent CA path length constraint")
		}
	}
	root := chain[len(chain)-1]
	if !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil {
		return errors.New("parent chain must end at a self-signed root CA")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, intermediate := range chain[1 : len(chain)-1] {
		intermediates.AddCert(intermediate)
	}
	_, err := certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("CA chain verification failed: %w", err)
	}
	return nil
}
