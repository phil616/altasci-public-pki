package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBundleDoesNotFetchAttackerAIA(t *testing.T) {
	var requests atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(404) }))
	defer trap.Close()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Unknown Issuer"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "SSRF Probe"},
		NotBefore: parent.NotBefore, NotAfter: parent.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, IssuingCertificateURL: []string{trap.URL + "/internal"}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"certificates_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
	w := httptest.NewRecorder()
	(&Server{}).bundleCertificates(w, httptest.NewRequest("POST", "http://console.test/api/v1/utilities/bundle", bytes.NewReader(body)))
	if w.Code != 422 || requests.Load() != 0 {
		t.Fatalf("untrusted AIA was fetched: status=%d requests=%d", w.Code, requests.Load())
	}
}

func TestCSRRejectsUnboundedRSA(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).generateCSR(w, httptest.NewRequest("POST", "http://console.test/", bytes.NewBufferString(`{"algorithm":"rsa","key_size":1000000000}`)))
	if w.Code != 422 {
		t.Fatalf("unbounded RSA accepted: %d", w.Code)
	}
}

func TestExpensiveOperationBound(t *testing.T) {
	s := &Server{cryptoSlots: make(chan struct{}, 1)}
	s.cryptoSlots <- struct{}{}
	called := false
	h := s.limitExpensive(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://test/", nil))
	if called || w.Code != 429 {
		t.Fatalf("busy work was accepted: called=%v status=%d", called, w.Code)
	}
	<-s.cryptoSlots
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://test/", nil))
	if !called || len(s.cryptoSlots) != 0 {
		t.Fatal("slot was not released")
	}
}

func TestRateAndMetricCardinalityBound(t *testing.T) {
	s := &Server{rates: make(map[string]rateWindow)}
	for i := 0; i < 4096; i++ {
		if ok, _ := s.allowRequest(fmt.Sprint(i), 1, time.Minute); !ok {
			t.Fatal("rate map filled prematurely")
		}
	}
	if ok, _ := s.allowRequest("overflow", 1, time.Minute); ok || len(s.rates) > 4096 {
		t.Fatal("rate map is unbounded")
	}
	if metricMethod("attacker-controlled-method") != "OTHER" || metricMethod("GET") != "GET" {
		t.Fatal("metric labels are not bounded")
	}
}

func TestProfileSecondsCannotWrapDuration(t *testing.T) {
	if err := (profileInput{DefaultValiditySeconds: 18446744074, MaxValiditySeconds: 18446744075}).validateSeconds(); err == nil {
		t.Fatal("overflowing validity was accepted")
	}
}
