package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/cloudflare/cfssl/console/security"
	"math/big"
	"strings"
	"testing"
	"time"
)

type importTestCA struct {
	cert            *x509.Certificate
	key             crypto.Signer
	certPEM, keyPEM string
}

func newImportTestCA(t *testing.T, parent *importTestCA, key crypto.Signer, configure func(*x509.Certificate)) *importTestCA {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Imported CA " + serial.String(), Organization: []string{"Existing Organization"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: -1}
	if configure != nil {
		configure(template)
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &importTestCA{cert: certificate, key: key,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}
}

func importTestInput(ca *importTestCA) ImportCAInput {
	return ImportCAInput{Name: "Existing CA", Slug: "existing-ca", Kind: "root", CertificatePEM: ca.certPEM, PrivateKeyPEM: ca.keyPEM}
}

func TestValidateCAImport(t *testing.T) {
	root := newImportTestCA(t, nil, nil, nil)
	other := newImportTestCA(t, nil, nil, nil)
	input := importTestInput(root)
	if cert, _, err := validateCAImport(input, time.Now()); err != nil || cert.MaxPathLen != -1 {
		t.Fatalf("unconstrained root import failed: %v", err)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*ImportCAInput)
	}{
		{"empty name", "name", func(i *ImportCAInput) { i.Name = " " }},
		{"bad slug", "slug", func(i *ImportCAInput) { i.Slug = "-bad" }},
		{"bad kind", "kind", func(i *ImportCAInput) { i.Kind = "leaf" }},
		{"root parent", "parent", func(i *ImportCAInput) { i.ParentCAID = "parent" }},
		{"missing parent", "parent", func(i *ImportCAInput) { i.Kind = "intermediate" }},
		{"missing cert", "certificate", func(i *ImportCAInput) { i.CertificatePEM = "" }},
		{"multiple certs", "exactly one", func(i *ImportCAInput) { i.CertificatePEM += root.certPEM }},
		{"leading garbage", "exactly one", func(i *ImportCAInput) { i.CertificatePEM = "garbage\n" + i.CertificatePEM }},
		{"trailing garbage", "exactly one", func(i *ImportCAInput) { i.CertificatePEM += "garbage" }},
		{"mismatched key", "match", func(i *ImportCAInput) { i.PrivateKeyPEM = other.keyPEM }},
		{"missing key", "private key", func(i *ImportCAInput) { i.PrivateKeyPEM = "" }},
		{"multiple keys", "one unencrypted", func(i *ImportCAInput) { i.PrivateKeyPEM += root.keyPEM }},
		{"encrypted key", "one unencrypted", func(i *ImportCAInput) {
			i.PrivateKeyPEM = strings.ReplaceAll(root.keyPEM, "PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := input
			tc.change(&invalid)
			if _, _, err := validateCAImport(invalid, time.Now()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
	for _, tc := range []struct {
		name, want string
		configure  func(*x509.Certificate)
	}{
		{"leaf certificate", "must be a CA", func(c *x509.Certificate) { c.IsCA = false }},
		{"no cert signing", "usages", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign }},
		{"no CRL signing", "usages", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign }},
		{"expired", "expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"future", "not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }},
		{"no SKI", "Subject Key Identifier", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{4, 0}}}
		}},
		{"critical extension", "critical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newImportTestCA(t, nil, nil, tc.configure)
			if _, _, err := validateCAImport(importTestInput(ca), time.Now()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
	issued := newImportTestCA(t, root, nil, nil)
	if _, _, err := validateCAImport(importTestInput(issued), time.Now()); err == nil || !strings.Contains(err.Error(), "self-signature") {
		t.Fatalf("non-self-signed root accepted: %v", err)
	}
}

func TestImportKeyFormatsAndAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCA := newImportTestCA(t, nil, rsaKey, nil)
	rsaCA.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	if _, _, err := validateCAImport(importTestInput(rsaCA), time.Now()); err != nil {
		t.Fatalf("PKCS#1 RSA-2048: %v", err)
	}
	ecCA := newImportTestCA(t, nil, nil, nil)
	ecDER, _ := x509.MarshalECPrivateKey(ecCA.key.(*ecdsa.PrivateKey))
	ecCA.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))
	if _, _, err := validateCAImport(importTestInput(ecCA), time.Now()); err != nil {
		t.Fatalf("SEC1: %v", err)
	}
	weakKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakCA := newImportTestCA(t, nil, weakKey, nil)
	if _, _, err := validateCAImport(importTestInput(weakCA), time.Now()); err == nil {
		t.Fatal("weak RSA key accepted")
	}
}

func TestImportedChainConstraints(t *testing.T) {
	depth := func(n int) func(*x509.Certificate) {
		return func(c *x509.Certificate) { c.MaxPathLen = n; c.MaxPathLenZero = n == 0 }
	}
	root := newImportTestCA(t, nil, nil, depth(2))
	mid := newImportTestCA(t, root, nil, depth(1))
	issuer := newImportTestCA(t, mid, nil, depth(0))
	if err := validateImportedChain(issuer.cert, []byte(mid.certPEM+root.certPEM), time.Now()); err != nil {
		t.Fatalf("valid chain: %v", err)
	}
	other := newImportTestCA(t, nil, nil, nil)
	if err := validateImportedChain(issuer.cert, []byte(other.certPEM), time.Now()); err == nil {
		t.Fatal("unrelated parent accepted")
	}
	if err := validateImportedChain(issuer.cert, []byte(mid.certPEM), time.Now()); err == nil {
		t.Fatal("incomplete parent chain accepted")
	}
	for _, n := range []int{0, 1} {
		limitedRoot := newImportTestCA(t, nil, nil, depth(n))
		first := newImportTestCA(t, limitedRoot, nil, depth(1))
		last := newImportTestCA(t, first, nil, depth(0))
		if err := validateImportedChain(last.cert, []byte(first.certPEM+limitedRoot.certPEM), time.Now()); err == nil || !strings.Contains(err.Error(), "path length") {
			t.Fatalf("root depth %d bypassed: %v", n, err)
		}
		if n == 0 {
			if err := validateImportedChain(first.cert, []byte(limitedRoot.certPEM), time.Now()); err == nil {
				t.Fatal("zero-depth root accepted a CA")
			}
		}
	}
}

func TestIssuedCertificateHonorsEveryCAUsage(t *testing.T) {
	root := newImportTestCA(t, nil, nil, nil)
	issuer := newImportTestCA(t, root, nil, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} })
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		leaf := newImportTestCA(t, issuer, nil, func(c *x509.Certificate) {
			c.IsCA = false
			c.KeyUsage = x509.KeyUsageDigitalSignature
			c.ExtKeyUsage = []x509.ExtKeyUsage{usage}
			c.DNSNames = []string{"host.example.test"}
		})
		err := security.VerifyIssuedCertificate(leaf.cert, []byte(issuer.certPEM+root.certPEM), time.Now())
		if usage == x509.ExtKeyUsageServerAuth && err != nil {
			t.Fatalf("allowed EKU rejected: %v", err)
		}
		if usage == x509.ExtKeyUsageClientAuth && err == nil {
			t.Fatal("CA extended key usage constraint was ignored")
		}
	}
}
