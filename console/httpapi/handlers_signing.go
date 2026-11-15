package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/console/signing"
)

const signingTokenKey contextKey = "independent-signing-token"

func (s *Server) signingInfo(r *http.Request) signing.RequestInfo {
	return signing.RequestInfo{RequestID: requestID(r), IP: s.clientIP(r), UserAgent: r.UserAgent()}
}
func (s *Server) signingError(w http.ResponseWriter, r *http.Request, err error) {
	var fault *signing.Error
	if errors.As(err, &fault) {
		if fault.Status == 401 {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		if fault.Status == 429 {
			w.Header().Set("Retry-After", "60")
		}
		s.logger.Warn("independent signing request rejected", "request_id", requestID(r), "code", fault.Code)
		problem(w, fault.Status, fault.Code, fault.Detail)
		return
	}
	s.logger.Error("independent signing operation failed", "request_id", requestID(r), "error", err)
	problem(w, http.StatusInternalServerError, "signing_failed", "Unable to complete independent signing operation")
}
func (s *Server) signingRate(w http.ResponseWriter, r *http.Request) bool {
	if allowed, retry := s.allowRequest("independent-signing:"+s.clientIP(r), 60, time.Minute); !allowed {
		rateLimited(w, retry)
		return false
	}
	return true
}

// Authenticate before reserving shared cryptographic slots or reading bodies.
// The service rechecks owner, credential state and scope under transaction locks.
func (s *Server) requireSigningToken(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.signingRate(w, r) {
			return
		}
		values := r.Header.Values("Authorization")
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(values) != 1 || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) != 47 || !strings.HasPrefix(parts[1], "ist_") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			problem(w, 401, "signing_unauthorized", "An independent signing Bearer credential is required")
			return
		}
		if err := s.signing.CheckCredential(r.Context(), r.PathValue("id"), parts[1], scope); err != nil {
			s.signingError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), signingTokenKey, parts[1])))
	})
}
func signingToken(r *http.Request) string {
	value, _ := r.Context().Value(signingTokenKey).(string)
	return value
}

func (s *Server) listSigning(w http.ResponseWriter, r *http.Request) {
	items, err := s.signing.List(r.Context(), principal(r).User.ID)
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) getSigning(w http.ResponseWriter, r *http.Request) {
	item, err := s.signing.Get(r.Context(), principal(r).User.ID, r.PathValue("id"))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) createSigning(w http.ResponseWriter, r *http.Request) {
	var input signing.CreateInput
	if _, ok := decodeSigningJSON(w, r, &input); !ok {
		return
	}
	item, err := s.signing.Create(r.Context(), principal(r).User.ID, input, s.signingInfo(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 201, item)
}
func (s *Server) updateSigning(w http.ResponseWriter, r *http.Request) {
	var input signing.UpdateInput
	if _, ok := decodeSigningJSON(w, r, &input); !ok {
		return
	}
	item, err := s.signing.Update(r.Context(), principal(r).User.ID, r.PathValue("id"), input, s.signingInfo(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) listSigningCredentials(w http.ResponseWriter, r *http.Request) {
	items, err := s.signing.Credentials(r.Context(), principal(r).User.ID, r.PathValue("id"))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) createSigningCredential(w http.ResponseWriter, r *http.Request) {
	var input signing.CredentialInput
	if _, ok := decodeSigningJSON(w, r, &input); !ok {
		return
	}
	item, token, err := s.signing.CreateCredential(r.Context(), principal(r).User.ID, r.PathValue("id"), input, s.signingInfo(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]any{"credential": item, "token": token})
}
func (s *Server) revokeSigningCredential(w http.ResponseWriter, r *http.Request) {
	if err := s.signing.RevokeCredential(r.Context(), principal(r).User.ID, r.PathValue("id"), r.PathValue("credentialID"), s.signingInfo(r)); err != nil {
		s.signingError(w, r, err)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) listSigningCertificates(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, next, err := s.signing.Certificates(r.Context(), principal(r).User.ID, r.PathValue("id"), r.URL.Query().Get("before"), limit)
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}
func (s *Server) revokeSigningCertificate(w http.ResponseWriter, r *http.Request) {
	var input signing.RevokeInput
	if _, ok := decodeSigningJSON(w, r, &input); !ok {
		return
	}
	item, err := s.signing.Revoke(r.Context(), principal(r).User.ID, r.PathValue("id"), r.PathValue("certificateID"), "", input.Reason, s.signingInfo(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) issueSigning(w http.ResponseWriter, r *http.Request) {
	var input signing.IssueInput
	raw, ok := decodeSigningJSON(w, r, &input)
	if !ok {
		return
	}
	item, replayed, err := s.signing.Issue(r.Context(), r.PathValue("id"), signingToken(r), r.Header.Get("Idempotency-Key"), input, raw, s.signingInfo(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	w.Header().Set("Idempotency-Replayed", strconv.FormatBool(replayed))
	writeJSON(w, 201, item)
}
func (s *Server) readSigningCertificate(w http.ResponseWriter, r *http.Request) {
	item, err := s.signing.PublicCertificate(r.Context(), r.PathValue("id"), r.PathValue("certificateID"), signingToken(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) publicRevokeSigningCertificate(w http.ResponseWriter, r *http.Request) {
	var input signing.RevokeInput
	if _, ok := decodeSigningJSON(w, r, &input); !ok {
		return
	}
	item, err := s.signing.Revoke(r.Context(), "", r.PathValue("id"), r.PathValue("certificateID"), signingToken(r), input.Reason, s.signingInfo(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) signingIssuer(w http.ResponseWriter, r *http.Request) {
	if !s.signingRate(w, r) {
		return
	}
	der, err := s.signing.Issuer(r.Context(), r.PathValue("id"))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	_, _ = w.Write(der) // #nosec G705 -- X.509 DER with application/pkix-* and global nosniff; never HTML.
}
func (s *Server) signingCRL(w http.ResponseWriter, r *http.Request) {
	if !s.signingRate(w, r) {
		return
	}
	der, err := s.signing.CRL(r.Context(), r.PathValue("id"), s.signingInfo(r))
	if err != nil {
		s.signingError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der) // #nosec G705 -- X.509 DER with application/pkix-* and global nosniff; never HTML.
}
