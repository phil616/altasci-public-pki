package signing

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

type authority struct {
	cert          *x509.Certificate
	chain         []*x509.Certificate
	key           crypto.Signer
	pem, chainPEM string
}

func parseCertificates(value string) ([]*x509.Certificate, error) {
	data := bytes.TrimSpace([]byte(value))
	out := []*x509.Certificate{}
	for len(data) > 0 {
		if len(out) >= 8 || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, invalid("CA chain must contain at most eight ordered PEM certificates")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, invalid("Invalid CA PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, invalid("Invalid CA certificate")
		}
		out = append(out, cert)
		data = bytes.TrimSpace(rest)
	}
	return out, nil
}

func loadAuthority(certPEM, keyPEM, chainPEM string, now time.Time) (authority, error) {
	var a authority
	certs, err := parseCertificates(certPEM)
	if err != nil || len(certs) != 1 {
		return a, invalid("Provide exactly one signing CA certificate")
	}
	a.cert = certs[0]
	parents, err := parseCertificates(chainPEM)
	if err != nil {
		return a, err
	}
	if len(parents) > 0 && bytes.Equal(parents[0].Raw, a.cert.Raw) {
		parents = parents[1:]
	}
	a.chain = append(certs, parents...)
	if len(a.chain) > 8 {
		return a, invalid("CA chain is too long")
	}
	seen := map[string]bool{}
	subordinateCAs := 0
	for i, cert := range a.chain {
		fingerprint := sha256.Sum256(cert.Raw)
		if seen[string(fingerprint[:])] {
			return a, invalid("Repeated CA in chain")
		}
		seen[string(fingerprint[:])] = true
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || len(cert.SubjectKeyId) == 0 || len(cert.UnhandledCriticalExtensions) != 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return a, invalid("CA chain contains an invalid, expired or unsupported CA")
		}
		if err := checkKey(cert.PublicKey); err != nil {
			return a, err
		}
		if i+1 < len(a.chain) {
			if err := checkKey(a.chain[i+1].PublicKey); err != nil {
				return a, err
			}
			parent := a.chain[i+1]
			if !bytes.Equal(cert.RawIssuer, parent.RawSubject) || cert.CheckSignatureFrom(parent) != nil || (len(cert.AuthorityKeyId) > 0 && !bytes.Equal(cert.AuthorityKeyId, parent.SubjectKeyId)) {
				return a, invalid("CA chain must be ordered from signer to its actual parent")
			}
			if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				subordinateCAs++
			}
			if (parent.MaxPathLen > 0 || parent.MaxPathLenZero) && subordinateCAs > parent.MaxPathLen {
				return a, invalid("CA chain exceeds an ancestor path length constraint")
			}

		}
		a.chainPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	root := a.chain[len(a.chain)-1]
	if !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil {
		return a, invalid("Complete chain must end in a self-signed root")
	}
	if a.cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return a, invalid("Signing CA requires CRL-signing usage")
	}
	if err := a.verify(a.cert, now, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}); err != nil {
		return a, invalid("CA chain constraints are invalid")
	}
	block, rest := pem.Decode([]byte(keyPEM))
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !slices.Contains([]string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"}, block.Type) || !bytes.HasPrefix(bytes.TrimSpace([]byte(keyPEM)), []byte("-----BEGIN ")) {
		return a, invalid("Provide one matching unencrypted PEM private key")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return a, invalid("Private key does not match signing CA")
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return a, invalid("Unsupported signing key")
	}
	a.key = key
	a.pem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}))
	return a, nil
}

func (a authority) verify(cert *x509.Certificate, now time.Time, usages []x509.ExtKeyUsage) error {
	roots := x509.NewCertPool()
	roots.AddCert(a.chain[len(a.chain)-1])
	intermediates := x509.NewCertPool()
	for _, parent := range a.chain[:len(a.chain)-1] {
		intermediates.AddCert(parent)
	}
	expected := a.chain
	if !bytes.Equal(cert.Raw, a.cert.Raw) {
		expected = append([]*x509.Certificate{cert}, a.chain...)
	}
	for _, usage := range usages {
		paths, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
		if err != nil {
			return err
		}
		matched := false
		for _, path := range paths {
			if len(path) != len(expected) {
				continue
			}
			equal := true
			for index, item := range path {
				if !bytes.Equal(item.Raw, expected[index].Raw) {
					equal = false
					break
				}
			}
			if equal {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("verification omitted a configured CA or its constraints")
		}
	}
	return nil
}

func (a authority) earliestExpiry() time.Time {
	expiry := a.cert.NotAfter
	for _, cert := range a.chain {
		if cert.NotAfter.Before(expiry) {
			expiry = cert.NotAfter
		}
	}
	return expiry
}

func (a authority) issue(csr *x509.CertificateRequest, instance string, base string, seconds int64, ekus []string, now time.Time) (Certificate, error) {
	var result Certificate
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return result, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	start := now.Add(-5 * time.Minute)
	end := now.Add(time.Duration(seconds) * time.Second)
	for _, cert := range a.chain {
		if cert.NotBefore.After(start) {
			start = cert.NotBefore
		}
		if cert.NotAfter.Before(end) {
			end = cert.NotAfter
		}
	}
	if !end.After(now) {
		return result, invalid("CA chain has expired")
	}
	usage := x509.KeyUsageDigitalSignature
	if csr.PublicKeyAlgorithm == x509.RSA && slices.Contains(ekus, "server_auth") {
		usage |= x509.KeyUsageKeyEncipherment
	}
	extended := []x509.ExtKeyUsage{}
	for _, eku := range ekus {
		if eku == "server_auth" {
			extended = append(extended, x509.ExtKeyUsageServerAuth)
		} else {
			extended = append(extended, x509.ExtKeyUsageClientAuth)
		}
	}
	public, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return result, err
	}
	ski := sha256.Sum256(public)
	template := &x509.Certificate{SerialNumber: serial, Subject: csr.Subject, NotBefore: start, NotAfter: end,
		BasicConstraintsValid: true, IsCA: false, KeyUsage: usage, ExtKeyUsage: extended,
		DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses, EmailAddresses: csr.EmailAddresses, URIs: csr.URIs,
		SubjectKeyId: ski[:20], AuthorityKeyId: a.cert.SubjectKeyId,
		CRLDistributionPoints: []string{base + "/signing/" + instance + "/crl"}, IssuingCertificateURL: []string{base + "/signing/" + instance + "/issuer.cer"}}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return result, fmt.Errorf("create independent certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return result, err
	}
	if err := a.verify(leaf, now, extended); err != nil {
		return result, invalid("Issued certificate violates CA chain constraints or permitted EKUs")
	}
	fingerprint := sha256.Sum256(der)
	result = Certificate{InstanceID: instance, Serial: serial.String(), CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), FingerprintSHA256: hex.EncodeToString(fingerprint[:]), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Status: "good"}
	result.ChainPEM = result.CertificatePEM + a.chainPEM
	return result, nil
}

// Scope revocation information to this instance even when the same issuer/key
// is independently imported elsewhere. RFC 5280 5.2.5, fullName URI and user certs.
func issuingDistributionPoint(uri string) []byte {
	name, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(uri)})
	fullName, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: name})
	point, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: fullName})
	onlyUsers, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 1, Bytes: []byte{0xff}})
	der, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(point, onlyUsers...)})
	return der
}
