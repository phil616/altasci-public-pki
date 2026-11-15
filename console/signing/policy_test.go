package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testPolicy() Policy {
	return Policy{Version: 1, AllowedDNSNames: []string{"example.test", "*.example.test"}, ExtendedKeyUsages: []string{"server_auth"}, DefaultValiditySeconds: 3600, MaxValiditySeconds: 7200, MaxSANs: 4}
}
func testCA(t *testing.T, change func(*x509.Certificate)) CreateInput {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Independent Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	if change != nil {
		change(cert)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return CreateInput{Name: "Independent test", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), Policy: testPolicy()}
}
func testCSR(t *testing.T, change func(*x509.CertificateRequest)) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "www.example.test"}, DNSNames: []string{"www.example.test"}}
	if change != nil {
		change(csr)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestPolicyIdentityBoundaries(t *testing.T) {
	p := testPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"www.example.test", "example.test"} {
		if !allowedDNS(name, p) {
			t.Fatal("valid DNS rejected", name)
		}
	}
	for _, name := range []string{"evil-example.test", "deep.www.example.test", "*.example.test", "example.test.evil"} {
		if allowedDNS(name, p) {
			t.Fatal("DNS escape accepted", name)
		}
	}
	p.AllowWildcards = true
	if !allowedDNS("*.example.test", p) {
		t.Fatal("explicit wildcard denied")
	}
	for _, value := range []string{"*.a.*.test", "127.0.0.1", "name_underscore.test", "-bad.test", " name.test", "name..test"} {
		if _, err := dnsName(value, true); err == nil {
			t.Fatal("invalid DNS accepted", value)
		}
	}
	name, err := dnsName("BÜCHER.Example", false)
	if err != nil || name != "xn--bcher-kva.example" {
		t.Fatal(name, err)
	}
	p.AllowedDNSNames = nil
	if err := p.Validate(); err == nil {
		t.Fatal("empty identity policy accepted")
	}
}
func TestCSRPolicyAndExtensionRejection(t *testing.T) {
	p := testPolicy()
	_ = p.Validate()
	for _, change := range []func(*x509.CertificateRequest){
		func(c *x509.CertificateRequest) { c.Subject.CommonName = "admin.evil.test" },
		func(c *x509.CertificateRequest) { c.DNSNames = []string{"deep.www.example.test"} },
		func(c *x509.CertificateRequest) {
			c.DNSNames = []string{"*.example.test"}
			c.Subject.CommonName = "*.example.test"
		},
		func(c *x509.CertificateRequest) { c.DNSNames = nil },
		func(c *x509.CertificateRequest) { c.EmailAddresses = []string{"a@example.test"} },
		func(c *x509.CertificateRequest) {
			c.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "hidden"}}
		},
		func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 3, 1, 1, 0xff}}}
		},
		func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 3, 0x88, 1, 1}}}
		},
	} {
		csr, err := parseCSR(testCSR(t, change))
		if err == nil {
			err = validateRequest(csr, p)
		}
		if err == nil {
			t.Fatal("unsafe CSR accepted")
		}
	}
	csr, err := parseCSR(testCSR(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err = validateRequest(csr, p); err != nil {
		t.Fatal(err)
	}
	bad := testCSR(t, nil)
	bad = strings.Replace(bad, "A", "B", 1)
	if _, err := parseCSR(bad); err == nil {
		t.Fatal("corrupted CSR accepted")
	}
}
func TestURIPrefixDoesNotEscape(t *testing.T) {
	p := testPolicy()
	p.AllowedURIPrefixes = []string{"spiffe://example.test/workloads"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"spiffe://example.test/workloads-evil", "spiffe://example.test.evil/workloads/a"} {
		u, _ := url.Parse(name)
		csr, err := parseCSR(testCSR(t, func(c *x509.CertificateRequest) { c.URIs = []*url.URL{u} }))
		if err == nil {
			err = validateRequest(csr, p)
		}
		if err == nil {
			t.Fatal("URI escaped policy", name)
		}
	}
	for _, name := range []string{"https://user@example.test/a", "https://example.test:443/a", "spiffe://example.test/a/../workloads", "https://example.test/a%2fb", "https://example.test/a?x=1", "spiffe://example.test/中文"} {
		if _, err := uriName(name); err == nil {
			t.Fatal("ambiguous URI accepted", name)
		}
	}
}
func TestAuthorityConstraintsAndDedicatedURLs(t *testing.T) {
	input := testCA(t, func(c *x509.Certificate) {
		c.PermittedDNSDomainsCritical = true
		c.PermittedDNSDomains = []string{".example.test"}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.OCSPServer = []string{"https://system.example/ocsp"}
		c.CRLDistributionPoints = []string{"https://system.example/crl"}
	})
	a, err := loadAuthority(input.CertificatePEM, input.PrivateKeyPEM, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := parseCSR(testCSR(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.issue(csr, "instance", "https://public.example", 3600, []string{"server_auth"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(result.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.OCSPServer) != 0 || leaf.CRLDistributionPoints[0] != "https://public.example/signing/instance/crl" || leaf.IsCA {
		t.Fatal("system endpoints or CA privilege leaked into leaf")
	}
	if _, err = a.issue(csr, "instance", "https://public.example", 3600, []string{"client_auth"}, time.Now()); err == nil {
		t.Fatal("ancestor EKU bypass")
	}
	csr, _ = parseCSR(testCSR(t, func(c *x509.CertificateRequest) {
		c.DNSNames = []string{"outside.test"}
		c.Subject.CommonName = "outside.test"
	}))
	if _, err = a.issue(csr, "instance", "https://public.example", 3600, []string{"server_auth"}, time.Now()); err == nil {
		t.Fatal("ancestor DNS constraint bypass")
	}
	if _, err = loadAuthority(input.CertificatePEM, input.PrivateKeyPEM, input.CertificatePEM+input.CertificatePEM, time.Now()); err == nil {
		t.Fatal("duplicate chain accepted")
	}
}

func TestChainCannotOmitConstrainedOrForbiddenIssuer(t *testing.T) {
	for _, mode := range []string{"path-length", "same-key-shortcut"} {
		t.Run(mode, func(t *testing.T) {
			rootInput := testCA(t, func(c *x509.Certificate) {
				if mode == "path-length" {
					c.MaxPathLen = 0
					c.MaxPathLenZero = true
				}
			})
			rootBlock, _ := pem.Decode([]byte(rootInput.CertificatePEM))
			root, err := x509.ParseCertificate(rootBlock.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			keyBlock, _ := pem.Decode([]byte(rootInput.PrivateKeyPEM))
			parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			rootKey := parsedKey.(*ecdsa.PrivateKey)
			childKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			child := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "Child CA"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{5, 6, 7, 8}}
			if mode == "same-key-shortcut" {
				childKey = rootKey
				child.Subject = root.Subject
				child.SubjectKeyId = root.SubjectKeyId
				child.PermittedDNSDomainsCritical = true
				child.PermittedDNSDomains = []string{".restricted.test"}
			}
			der, err := x509.CreateCertificate(rand.Reader, child, root, childKey.Public(), rootKey)
			if err != nil {
				t.Fatal(err)
			}
			pkcs8, err := x509.MarshalPKCS8PrivateKey(childKey)
			if err != nil {
				t.Fatal(err)
			}
			a, err := loadAuthority(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), rootInput.CertificatePEM, time.Now())
			if mode == "path-length" {
				if err == nil {
					t.Fatal("import ignored root path length constraint")
				}
				return
			}
			if err != nil {
				return
			} // Rejecting an ambiguous same-key chain is also safe.
			csr, err := parseCSR(testCSR(t, nil))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.issue(csr, "instance", "https://public.example", 3600, []string{"server_auth"}, time.Now()); err == nil {
				t.Fatal("verification skipped constrained signing CA through same-key root")
			}
		})
	}
}

// Every accepted policy URI must remain accepted after persistence/normalization.
func TestPolicyURINormalizationIsStable(t *testing.T) {
	for _, value := range []string{"spiffe://example.test/workloads/[id]", "https://example.test/a\"b", "https://example.test/a#", "https://example.test/{id}", "https://example.test/\u0060id\u0060"} {
		if _, err := uriName(value); err == nil {
			t.Fatalf("noncanonical URI accepted: %q", value)
		}
	}
	for _, value := range []string{"spiffe://example.test/workloads/a", "https://EXAMPLE.test/workloads/", "https://bücher.example/path"} {
		first, err := uriName(value)
		if err != nil {
			t.Fatal(value, err)
		}
		second, err := uriName(first)
		if err != nil || second != first {
			t.Fatalf("normalization is not stable: %s -> %s, %v", value, first, err)
		}
	}
}
