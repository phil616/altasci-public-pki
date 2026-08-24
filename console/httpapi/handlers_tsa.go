package httpapi

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/console/tsa"
)

const maxTimestampRequestSize = 64 << 10

func (s *Server) listTimestampAuthorities(w http.ResponseWriter, r *http.Request) {
	items, err := s.tsa.ListAuthorities(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list timestamp authorities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createTimestampAuthority(w http.ResponseWriter, r *http.Request) {
	var input tsa.CreateAuthorityInput
	if !decodeJSON(w, r, &input) {
		return
	}
	input.CAID = r.PathValue("id")
	authority, err := s.tsa.CreateAuthority(r.Context(), principal(r).User, input)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "timestamp_authority_creation_failed", err.Error())
		return
	}
	s.audit(r, "tsa.create", "timestamp_authority", &authority.ID, "success",
		map[string]string{"slug": authority.Slug, "policy_oid": authority.PolicyOID, "ca_id": authority.CAID})
	writeJSON(w, http.StatusCreated, authority)
}

func (s *Server) publicTimestamp(w http.ResponseWriter, r *http.Request) {
	if allowed, retry := s.allowRequest("tsa:"+s.clientIP(r), 120, time.Minute); !allowed {
		rateLimited(w, retry)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/timestamp-query" {
		problem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/timestamp-query")
		return
	}
	requestDER, err := io.ReadAll(io.LimitReader(r.Body, maxTimestampRequestSize+1))
	if err != nil {
		problem(w, http.StatusBadRequest, "request_read_failed", "Unable to read timestamp request")
		return
	}
	if len(requestDER) > maxTimestampRequestSize {
		problem(w, http.StatusRequestEntityTooLarge, "request_too_large", "Timestamp request exceeds 64 KiB")
		return
	}
	responseDER, internalErr := s.tsa.Respond(r.Context(), r.PathValue("slug"), requestDER)
	if internalErr != nil && !errors.Is(internalErr, r.Context().Err()) {
		s.logger.Warn("timestamp request rejected", "request_id", requestID(r), "tsa", r.PathValue("slug"), "error", internalErr)
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseDER)
}
