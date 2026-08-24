package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/helpers"
)

func (s *Server) listCAs(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListCAs(r.Context(), false)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list certificate authorities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getCA(w http.ResponseWriter, r *http.Request) {
	ca, err := s.store.CAByID(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "ca_not_found", "Certificate authority was not found")
		return
	}
	writeJSON(w, http.StatusOK, ca)
}

func (s *Server) createRoot(w http.ResponseWriter, r *http.Request) {
	var input pki.CreateCAInput
	if !decodeJSON(w, r, &input) {
		return
	}
	ca, err := s.pki.CreateRoot(r.Context(), principal(r).User, input)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "root_ca_creation_failed", err.Error())
		return
	}
	_, _ = s.pki.GenerateCRL(r.Context(), ca.ID)
	s.audit(r, "ca.root.create", "certificate_authority", &ca.ID, "success", map[string]string{"slug": ca.Slug})
	writeJSON(w, http.StatusCreated, ca)
}

func (s *Server) createIntermediate(w http.ResponseWriter, r *http.Request) {
	var input pki.CreateCAInput
	if !decodeJSON(w, r, &input) {
		return
	}
	ca, err := s.pki.CreateIntermediate(r.Context(), principal(r).User, input)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "intermediate_ca_creation_failed", err.Error())
		return
	}
	_, _ = s.pki.GenerateCRL(r.Context(), ca.ID)
	s.audit(r, "ca.intermediate.create", "certificate_authority", &ca.ID, "success", map[string]string{"slug": ca.Slug})
	writeJSON(w, http.StatusCreated, ca)
}

func (s *Server) exportCAKey(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	id := r.PathValue("id")
	if err := s.verifyRootStepUp(r, input.Password, input.TOTP); err != nil {
		s.audit(r, "ca.key.export", "certificate_authority", &id, "denied", nil)
		problem(w, http.StatusForbidden, "step_up_failed", "Fresh password, TOTP, and Cloudflare Access authentication are required")
		return
	}
	key, err := s.pki.ExportCAKey(r.Context(), id)
	if err != nil {
		problem(w, http.StatusNotFound, "ca_key_not_found", "CA key could not be exported")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ca-private-key.pem"`)
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	s.audit(r, "ca.key.export", "certificate_authority", &id, "success", nil)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(key)
}

func (s *Server) createCertificateRequest(w http.ResponseWriter, r *http.Request) {
	var input pki.CreateRequestInput
	if !decodeJSON(w, r, &input) {
		return
	}
	req, err := s.pki.CreateRequest(r.Context(), principal(r).User, input)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "certificate_request_invalid", err.Error())
		return
	}
	s.audit(r, "certificate_request.create", "certificate_request", &req.ID, "success", map[string]string{"ca_id": req.CAID})
	writeJSON(w, http.StatusCreated, req)
}

func (s *Server) listCertificateRequests(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRequests(r.Context(), principal(r).User)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list certificate requests")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getCertificateRequest(w http.ResponseWriter, r *http.Request) {
	req, err := s.store.RequestByID(r.Context(), r.PathValue("id"))
	if err != nil || !s.canViewRequest(r, req) {
		problem(w, http.StatusNotFound, "request_not_found", "Certificate request was not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) canViewRequest(r *http.Request, req store.CertificateRequest) bool {
	p := principal(r)
	if p.User.Role == "super_admin" || req.RequesterID == p.User.ID {
		return true
	}
	if p.User.Role == "operator" {
		allowed, _ := s.store.HasCAGrant(r.Context(), req.CAID, p.User.ID, "view_requests")
		return allowed
	}
	return false
}

func (s *Server) approveCertificateRequest(w http.ResponseWriter, r *http.Request) {
	s.decideCertificateRequest(w, r, "approved")
}

func (s *Server) rejectCertificateRequest(w http.ResponseWriter, r *http.Request) {
	s.decideCertificateRequest(w, r, "rejected")
}

func (s *Server) decideCertificateRequest(w http.ResponseWriter, r *http.Request, decision string) {
	var input struct {
		Comment string `json:"comment"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.DecideRequest(r.Context(), id, principal(r).User, decision, input.Comment); err != nil {
		s.audit(r, "certificate_request."+decision, "certificate_request", &id, "denied", nil)
		problem(w, http.StatusConflict, "request_decision_failed", err.Error())
		return
	}
	s.audit(r, "certificate_request."+decision, "certificate_request", &id, "success", nil)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "status": decision})
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListCertificates(r.Context(), principal(r).User)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list certificates")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listCertificateInventory(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "pending" && status != "issued" && status != "rejected" && status != "failed" {
		problem(w, http.StatusBadRequest, "invalid_inventory_status", "Status must be pending, issued, rejected, or failed")
		return
	}
	items, err := s.store.ListCertificateInventory(r.Context(), principal(r).User, status)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list certificate inventory")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.visibleCertificate(r, r.PathValue("id"))
	if !ok {
		problem(w, http.StatusNotFound, "certificate_not_found", "Certificate was not found")
		return
	}
	writeJSON(w, http.StatusOK, certificateResponse(cert))
}

func (s *Server) downloadCertificate(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.visibleCertificate(r, r.PathValue("id"))
	if !ok {
		problem(w, http.StatusNotFound, "certificate_not_found", "Certificate was not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="certificate-chain.pem"`)
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write([]byte(cert.ChainPEM))
}

func (s *Server) visibleCertificate(r *http.Request, id string) (store.Certificate, bool) {
	cert, err := s.store.CertificateByID(r.Context(), id)
	if err != nil {
		return store.Certificate{}, false
	}
	p := principal(r)
	if p.User.Role == "super_admin" || cert.OwnerUserID == p.User.ID {
		return cert, true
	}
	if p.User.Role == "operator" {
		allowed, _ := s.store.OperatorCanViewCertificate(r.Context(), cert.ID, p.User.ID)
		return cert, allowed
	}
	return store.Certificate{}, false
}

func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Reason  int    `json:"reason"`
		Comment string `json:"comment,omitempty"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	id := r.PathValue("id")
	cert, err := s.pki.Revoke(r.Context(), principal(r).User, id, input.Reason, input.Comment)
	if err != nil {
		s.audit(r, "certificate.revoke", "certificate", &id, "denied", nil)
		problem(w, http.StatusUnprocessableEntity, "revocation_failed", err.Error())
		return
	}
	s.audit(r, "certificate.revoke", "certificate", &id, "success", map[string]int{"reason": input.Reason})
	writeJSON(w, http.StatusOK, certificateResponse(cert))
}

func (s *Server) downloadPrivateKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	id := r.PathValue("id")
	cert, err := s.store.CertificateByID(r.Context(), id)
	if err != nil || cert.OwnerUserID != p.User.ID {
		problem(w, http.StatusNotFound, "private_key_not_found", "One-time private key artifact was not found")
		return
	}
	key, err := s.pki.DownloadLeafKey(r.Context(), id, p.User.ID)
	if err != nil {
		problem(w, http.StatusGone, "private_key_unavailable", "Private key was already downloaded or has expired")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="private-key.pem"`)
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	s.audit(r, "certificate.private_key.download", "certificate", &id, "success", nil)
	_, _ = w.Write(key)
}

func (s *Server) certInfo(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	cert, err := helpers.ParseCertificatePEM([]byte(input.CertificatePEM))
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_certificate", "Unable to parse certificate")
		return
	}
	fingerprint := sha256Fingerprint(cert.Raw)
	writeJSON(w, http.StatusOK, map[string]any{"subject": cert.Subject.String(), "issuer": cert.Issuer.String(),
		"serial": cert.SerialNumber.String(), "not_before": cert.NotBefore, "not_after": cert.NotAfter,
		"dns_names": cert.DNSNames, "email_addresses": cert.EmailAddresses,
		"ip_addresses": cert.IPAddresses, "uris": cert.URIs,
		"is_ca": cert.IsCA, "fingerprint_sha256": fingerprint})
}

func certificateResponse(cert store.Certificate) map[string]any {
	return map[string]any{"id": cert.ID, "issuer_ca_id": cert.IssuerCAID, "owner_user_id": cert.OwnerUserID,
		"request_id": cert.RequestID, "serial": cert.Serial, "fingerprint_sha256": hex.EncodeToString(cert.FingerprintSHA256),
		"certificate_pem": cert.CertificatePEM, "chain_pem": cert.ChainPEM, "subject": cert.Subject,
		"sans": cert.SANs, "not_before": cert.NotBefore, "not_after": cert.NotAfter, "status": cert.Status,
		"created_at": cert.CreatedAt}
}

func sha256Fingerprint(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func normalizeHex(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, ":", ""))
}
