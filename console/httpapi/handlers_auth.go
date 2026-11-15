package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/console/auth"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if allowed, retry := s.allowRequest("login:"+s.clientIP(r), 10, time.Minute); !allowed {
		rateLimited(w, retry)
		return
	}
	var input struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		TOTP     string `json:"totp,omitempty"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := s.auth.Login(r.Context(), auth.LoginInput{
		Login: input.Login, Password: input.Password, TOTP: input.TOTP,
		IP: s.clientIP(r), UserAgent: r.UserAgent(),
	})
	if err != nil {
		if errors.Is(err, auth.ErrSecondFactorRequired) {
			_ = s.auditLogin(r, nil, "denied")
			problem(w, http.StatusUnauthorized, "second_factor_required", "Super administrator login requires a fresh TOTP code (SHA-256, 6 digits, 30 seconds)")
			return
		}
		s.logger.Warn("login denied", "request_id", requestID(r), "error", err,
			"login_matches_root", strings.EqualFold(strings.TrimSpace(input.Login), s.config.RootUserEmail))
		_ = s.auditLogin(r, nil, "denied")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			problem(w, http.StatusServiceUnavailable, "authentication_unavailable", "Authentication is temporarily unavailable")
			return
		}
		problem(w, http.StatusUnauthorized, "invalid_credentials", "Login credentials or required second factors are invalid")
		return
	}
	if err := s.auditLogin(r, &result.User, "success"); err != nil {
		_ = s.auth.Logout(r.Context(), result.SessionID)
		problem(w, http.StatusServiceUnavailable, "audit_unavailable", "Audit storage is unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: result.Token, Path: "/",
		Secure: !s.config.DevelopmentInsecure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Expires: result.ExpiresAt, MaxAge: int(time.Until(result.ExpiresAt).Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"user": result.User, "csrf_token": result.CSRFToken,
		"expires_at": result.ExpiresAt})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if err := s.auth.Logout(r.Context(), p.SessionID); err != nil {
		problem(w, http.StatusInternalServerError, "logout_failed", "Unable to revoke session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/",
		Secure: !s.config.DevelopmentInsecure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: -1, Expires: time.Unix(1, 0)})
	_ = s.audit(r, "auth.logout", "session", &p.SessionID, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auditLogin(r *http.Request, user *store.User, outcome string) error {
	var actorID, role *string
	if user != nil {
		actorID, role = &user.ID, &user.Role
	}
	ip := s.clientIP(r)
	if err := s.store.Audit(r.Context(), store.AuditEvent{ActorUserID: actorID, ActorRole: role,
		Action: "auth.login", ResourceType: "session", Outcome: outcome, RequestID: requestID(r),
		SourceIP: &ip, UserAgent: r.UserAgent()}); err != nil {
		s.logger.Error("write login audit event", "request_id", requestID(r), "error", err)
		return err
	}
	return nil
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": principal(r).User})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can list users")
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list users")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can create users")
		return
	}
	var input struct {
		Username string  `json:"username"`
		Email    *string `json:"email,omitempty"`
		Role     string  `json:"role"`
		Password string  `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if len(input.Username) < 3 || len(input.Username) > 128 || len(input.Password) < 15 || len(input.Password) > 128 {
		problem(w, http.StatusUnprocessableEntity, "invalid_user", "Username must be 3-128 characters and password 15-128 characters")
		return
	}
	if input.Email != nil {
		value := strings.ToLower(strings.TrimSpace(*input.Email))
		if value == "" || !strings.Contains(value, "@") {
			problem(w, http.StatusUnprocessableEntity, "invalid_email", "Email address is invalid")
			return
		}
		input.Email = &value
	}
	hash, err := security.HashPassword(input.Password)
	if err != nil {
		problem(w, http.StatusInternalServerError, "password_hash_failed", "Unable to protect password")
		return
	}
	user, err := s.store.CreateUser(r.Context(), input.Username, input.Email, input.Role, hash)
	if err != nil {
		problem(w, http.StatusConflict, "user_conflict", "Username or email already exists, or role is invalid")
		return
	}
	_ = s.audit(r, "user.create", "user", &user.ID, "success", map[string]any{"role": user.Role})
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) setUserStatus(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can update users")
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.SetUserStatus(r.Context(), id, input.Status); err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		problem(w, status, "user_update_failed", "Unable to update user status")
		return
	}
	_ = s.audit(r, "user.status.update", "user", &id, "success", map[string]string{"status": input.Status})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can reset passwords")
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Password) < 15 || len(input.Password) > 128 {
		problem(w, http.StatusUnprocessableEntity, "invalid_password", "Password must contain 15-128 characters")
		return
	}
	hash, err := security.HashPassword(input.Password)
	if err != nil {
		problem(w, http.StatusInternalServerError, "password_hash_failed", "Unable to protect password")
		return
	}
	id := r.PathValue("id")
	if err := s.store.ResetUserPassword(r.Context(), id, hash); err != nil {
		problem(w, http.StatusNotFound, "user_not_found", "User was not found or is the protected root account")
		return
	}
	_ = s.audit(r, "user.password.reset", "user", &id, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can list CA grants")
		return
	}
	grants, err := s.store.ListCAGrants(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list CA grants")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": grants})
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can grant CA permissions")
		return
	}
	var input struct {
		UserID     string `json:"user_id"`
		Permission string `json:"permission"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	caID := r.PathValue("id")
	if err := s.store.GrantCA(r.Context(), caID, input.UserID, input.Permission, p.User.ID); err != nil {
		problem(w, http.StatusUnprocessableEntity, "grant_failed", "Grant is invalid; root CA permissions cannot be delegated")
		return
	}
	_ = s.audit(r, "ca.grant.create", "certificate_authority", &caID, "success", input)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can revoke CA grants")
		return
	}
	caID := r.PathValue("id")
	if err := s.store.RevokeCAGrant(r.Context(), caID, r.PathValue("userID"), r.PathValue("permission")); err != nil {
		problem(w, http.StatusNotFound, "grant_not_found", "CA grant was not found")
		return
	}
	_ = s.audit(r, "ca.grant.delete", "certificate_authority", &caID, "success",
		map[string]string{"user_id": r.PathValue("userID"), "permission": r.PathValue("permission")})
	w.WriteHeader(http.StatusNoContent)
}

// verifyRootStepUp requires a fresh password and non-replayed TOTP code.
func (s *Server) verifyRootStepUp(r *http.Request, password, code string) error {
	p := principal(r)
	if p.User.Role != "super_admin" {
		return errors.New("super administrator is required")
	}
	if allowed, _ := s.allowRequest("step-up:"+p.User.ID, 5, time.Minute); !allowed {
		return errors.New("too many step-up attempts; retry later")
	}
	fresh, err := s.store.UserByID(r.Context(), p.User.ID)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(s.config.RootUserTOTPSecret)
	if len(fresh.RootTOTPSecretHash) > 0 && subtle.ConstantTimeCompare(fresh.RootTOTPSecretHash, digest[:]) != 1 {
		return errors.New("root TOTP configuration changed; restart this process")
	}
	ok, err := security.VerifyPassword(password, fresh.PasswordHash)
	if err != nil || !ok {
		return errors.New("invalid password")
	}
	step, err := security.VerifyTOTP(s.config.RootUserTOTPSecret, code, time.Now(), fresh.TOTPLastStep)
	if err != nil {
		return err
	}
	return s.store.AcceptRootStepUp(r.Context(), fresh.ID, fresh.PasswordHash, fresh.RootTOTPSecretHash, step)
}
