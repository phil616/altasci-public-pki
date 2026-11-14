package security

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

func parseIssuerChain(value []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for len(bytes.TrimSpace(value)) != 0 {
		value = bytes.TrimSpace(value)
		block, rest := pem.Decode(value)
		if !bytes.HasPrefix(value, []byte("-----BEGIN CERTIFICATE-----")) || block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid issuer chain PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain, value = append(chain, cert), rest
	}
	if len(chain) == 0 {
		return nil, errors.New("issuer chain is empty")
	}
	return chain, nil
}

// ChainNotAfter limits newly issued certificates to the lifetime of every
// ancestor, including imported CAs whose issuer expires before they do.
func ChainNotAfter(value []byte) (time.Time, error) {
	chain, err := parseIssuerChain(value)
	if err != nil {
		return time.Time{}, err
	}
	expires := chain[0].NotAfter
	for _, cert := range chain[1:] {
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
	}
	return expires, nil
}

// VerifyIssuedCertificate verifies the exact configured issuer chain, including
// name constraints and every declared extended key usage. Trust never falls back
// to machine roots or a network fetch.
func VerifyIssuedCertificate(cert *x509.Certificate, issuerPEM []byte, now time.Time) error {
	chain, err := parseIssuerChain(issuerPEM)
	if err != nil {
		return err
	}
	child := cert
	subordinateCAs := 0
	for _, parent := range chain {
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) || child.CheckSignatureFrom(parent) != nil {
			return errors.New("certificate does not match configured issuer chain")
		}
		if child.IsCA && !bytes.Equal(child.RawIssuer, child.RawSubject) {
			subordinateCAs++
		}
		if (parent.MaxPathLen > 0 || parent.MaxPathLenZero) && subordinateCAs > parent.MaxPathLen {
			return errors.New("certificate exceeds an ancestor path length constraint")
		}
		child = parent
	}
	root := chain[len(chain)-1]
	if !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil {
		return errors.New("issuer chain does not end at a self-signed root")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, ca := range chain[:len(chain)-1] {
		intermediates.AddCert(ca)
	}
	usages := cert.ExtKeyUsage
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	for _, usage := range usages {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
			CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return fmt.Errorf("issued certificate violates its CA chain: %w", err)
		}
	}
	return nil
}
