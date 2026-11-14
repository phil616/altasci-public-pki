package httpapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/helpers"
	"golang.org/x/crypto/ocsp"
)

func (s *Server) publicAuthorities(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListCAs(r.Context(), true)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list certificate authorities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) publicCertificateByFingerprint(w http.ResponseWriter, r *http.Request) {
	value := normalizeHex(r.PathValue("fingerprint"))
	if len(value) != 64 {
		problem(w, http.StatusBadRequest, "invalid_fingerprint", "SHA-256 fingerprint must contain 64 hexadecimal characters")
		return
	}
	digest, err := hex.DecodeString(value)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_fingerprint", "SHA-256 fingerprint is invalid")
		return
	}
	cert, err := s.store.CertificateByFingerprint(r.Context(), digest)
	if err != nil {
		problem(w, http.StatusNotFound, "certificate_not_found", "Certificate was not found")
		return
	}
	writeJSON(w, http.StatusOK, certificateResponse(cert))
}

func (s *Server) publicCertificateBySerial(w http.ResponseWriter, r *http.Request) {
	ca, err := s.store.CABySlug(r.Context(), r.PathValue("issuer"))
	if err != nil {
		problem(w, http.StatusNotFound, "issuer_not_found", "Issuer was not found")
		return
	}
	cert, err := s.store.CertificateByIssuerSerial(r.Context(), ca.ID, r.PathValue("serial"))
	if err != nil {
		problem(w, http.StatusNotFound, "certificate_not_found", "Certificate was not found")
		return
	}
	writeJSON(w, http.StatusOK, certificateResponse(cert))
}

func (s *Server) publicCertificateStatus(w http.ResponseWriter, r *http.Request) {
	ca, err := s.store.CABySlug(r.Context(), r.PathValue("issuer"))
	if err != nil {
		problem(w, http.StatusNotFound, "issuer_not_found", "Issuer was not found")
		return
	}
	cert, err := s.store.CertificateByIssuerSerial(r.Context(), ca.ID, r.PathValue("serial"))
	if err != nil {
		problem(w, http.StatusNotFound, "certificate_not_found", "Certificate was not found")
		return
	}
	status := cert.Status
	if time.Now().After(cert.NotAfter) && status == "good" {
		status = "expired"
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuer": ca.Slug, "serial": cert.Serial,
		"status": status, "not_before": cert.NotBefore, "not_after": cert.NotAfter})
}

func (s *Server) publicIssuer(w http.ResponseWriter, r *http.Request) {
	slug, ok := strings.CutSuffix(r.PathValue("file"), ".cer")
	if !ok || slug == "" {
		problem(w, http.StatusNotFound, "issuer_not_found", "Issuer certificate was not found")
		return
	}
	ca, err := s.store.CABySlug(r.Context(), slug)
	if err != nil || ca.Status == "destroyed" {
		problem(w, http.StatusNotFound, "issuer_not_found", "Issuer certificate was not found")
		return
	}
	cert, err := helpers.ParseCertificatePEM([]byte(ca.CertificatePEM))
	if err != nil {
		problem(w, http.StatusInternalServerError, "invalid_issuer", "Stored issuer certificate is invalid")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("ETag", `"`+sha256Fingerprint(cert.Raw)+`"`)
	_, _ = w.Write(cert.Raw)
}

func (s *Server) publicCRL(w http.ResponseWriter, r *http.Request) {
	slug, ok := strings.CutSuffix(r.PathValue("file"), ".crl")
	if !ok || slug == "" {
		problem(w, http.StatusNotFound, "issuer_not_found", "CRL issuer was not found")
		return
	}
	ca, err := s.store.CABySlug(r.Context(), slug)
	if err != nil || ca.Status == "destroyed" {
		problem(w, http.StatusNotFound, "issuer_not_found", "CRL issuer was not found")
		return
	}
	der, next, err := s.store.CurrentCRL(r.Context(), ca.ID)
	if errors.Is(err, store.ErrNotFound) || (!next.IsZero() && next.Before(time.Now().Add(time.Minute))) {
		der, err = s.pki.GenerateCRL(r.Context(), ca.ID)
		if err == nil {
			var parsed *x509.RevocationList
			parsed, err = x509.ParseRevocationList(der)
			if err == nil {
				next = parsed.NextUpdate
			}
		}
	}
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "crl_unavailable", "Current CRL is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(max(0, min(3600, int(time.Until(next).Seconds())))))
	w.Header().Set("Expires", next.UTC().Format(http.TimeFormat))
	_, _ = w.Write(der)
}

func (s *Server) publicOCSP(w http.ResponseWriter, r *http.Request) {
	if allowed, retry := s.allowRequest("ocsp:"+s.clientIP(r), 120, time.Minute); !allowed {
		rateLimited(w, retry)
		return
	}
	ca, err := s.store.CABySlug(r.Context(), r.PathValue("slug"))
	if err != nil || ca.Status != "active" {
		writeOCSPError(w, ocsp.UnauthorizedErrorResponse)
		return
	}
	var requestDER []byte
	if r.Method == http.MethodPost {
		requestDER, err = io.ReadAll(io.LimitReader(r.Body, 16<<10))
	} else {
		encoded, unescapeErr := url.PathUnescape(r.PathValue("request"))
		if unescapeErr != nil {
			writeOCSPError(w, ocsp.MalformedRequestErrorResponse)
			return
		}
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			if requestDER, err = encoding.DecodeString(encoded); err == nil {
				break
			}
		}
	}
	if err != nil || len(requestDER) == 0 {
		writeOCSPError(w, ocsp.MalformedRequestErrorResponse)
		return
	}
	request, err := pki.ParseOCSPRequest(requestDER)
	if err != nil {
		writeOCSPError(w, ocsp.MalformedRequestErrorResponse)
		return
	}
	cert, err := s.store.CertificateByIssuerSerial(r.Context(), ca.ID, request.SerialNumber.String())
	if err != nil {
		writeOCSPError(w, ocsp.UnauthorizedErrorResponse)
		return
	}
	issuer, issuerErr := helpers.ParseCertificatePEM([]byte(ca.CertificatePEM))
	leaf, leafErr := helpers.ParseCertificatePEM([]byte(cert.CertificatePEM))
	if issuerErr != nil || leafErr != nil {
		writeOCSPError(w, ocsp.InternalErrorErrorResponse)
		return
	}
	expectedDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: request.HashAlgorithm})
	if err != nil {
		writeOCSPError(w, ocsp.MalformedRequestErrorResponse)
		return
	}
	expected, err := ocsp.ParseRequest(expectedDER)
	if err != nil || !bytes.Equal(request.IssuerNameHash, expected.IssuerNameHash) ||
		!bytes.Equal(request.IssuerKeyHash, expected.IssuerKeyHash) {
		writeOCSPError(w, ocsp.UnauthorizedErrorResponse)
		return
	}
	response, err := s.pki.OCSPResponse(r.Context(), ca, cert, request.HashAlgorithm)
	if err != nil {
		writeOCSPError(w, ocsp.InternalErrorErrorResponse)
		return
	}
	parsedResponse, err := ocsp.ParseResponse(response, issuer)
	if err != nil {
		writeOCSPError(w, ocsp.InternalErrorErrorResponse)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(max(0, min(3600, int(time.Until(parsedResponse.NextUpdate).Seconds())))))
	_, _ = w.Write(response)
}

func writeOCSPError(w http.ResponseWriter, response []byte) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Pool().Ping(ctx); err != nil {
		problem(w, http.StatusServiceUnavailable, "database_unavailable", "PostgreSQL is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"name": "PKI-Console", "version": Version,
		"cfssl_upstream": CFSSLUpstream})
}

var (
	Version       = "dev"
	CFSSLUpstream = "e429e72785df640e0dd3320dc895d4dd03c66cdb"
)

func trimSpace(value string) string { return strings.TrimSpace(value) }
