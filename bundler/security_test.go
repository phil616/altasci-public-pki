package bundler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWithoutAIAFetching(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Offline Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); _, _ = w.Write(rootDER) }))
	defer trap.Close()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "offline.example.test"}, DNSNames: []string{"offline.example.test"},
		KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: root.NotBefore, NotAfter: root.NotAfter, IssuingCertificateURL: []string{trap.URL}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, rootCert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	offline, err := NewBundlerFromPEM(nil, nil, WithoutAIAFetching())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offline.BundleFromPEMorDER(leafPEM, nil, Optimal, ""); err == nil {
		t.Fatal("unknown root was trusted")
	}
	if requests.Load() != 0 {
		t.Fatal("offline bundler issued HTTP request")
	}
	trusted, err := NewBundlerFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), nil, WithoutAIAFetching())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.BundleFromPEMorDER(leafPEM, nil, Optimal, ""); err != nil {
		t.Fatalf("supplied trust chain failed: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("complete offline chain fetched an AIA")
	}
	legacy, err := NewBundlerFromPEM(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = legacy.BundleFromPEMorDER(leafPEM, nil, Optimal, "")
	if requests.Load() == 0 {
		t.Fatal("test fixture did not exercise AIA fetching")
	}
	otherD := new(big.Int).Sub(key.Curve.Params().N, key.D)
	x, y := key.Curve.ScalarBaseMult(otherD.Bytes())
	opposite := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: key.Curve, X: x, Y: y}, D: otherD}
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) == 0 {
		t.Fatal("invalid opposite-key fixture")
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.Bundle([]*x509.Certificate{leafCert}, opposite, Force); err == nil {
		t.Fatal("mismatched ECDSA private key with the same X coordinate accepted")
	}
	if _, err := trusted.Bundle(nil, nil, Force); err == nil {
		t.Fatal("empty bundle accepted")
	}
}
