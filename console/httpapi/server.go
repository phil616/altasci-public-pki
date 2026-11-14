// Package httpapi exposes the authenticated Console API and the deliberately
// small public PKI publication surface on separate hostnames.
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/console/auth"
	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/console/tsa"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	config          consoleconfig.Config
	store           *store.Store
	auth            *auth.Service
	pki             *pki.Service
	tsa             *tsa.Service
	logger          *slog.Logger
	console         *http.ServeMux
	public          *http.ServeMux
	consoleFrontend http.Handler
	publicFrontend  http.Handler
	rateMu          sync.Mutex
	rates           map[string]rateWindow
	rateSweep       time.Time
	cryptoSlots     chan struct{}
	metricsHandler  http.Handler
	requestCount    *prometheus.CounterVec
	requestLatency  *prometheus.HistogramVec
}

type rateWindow struct {
	Count int
	Reset time.Time
}

type contextKey string

const (
	principalKey contextKey = "principal"
	requestIDKey contextKey = "request-id"
)

func New(cfg consoleconfig.Config, data *store.Store, authService *auth.Service, pkiService *pki.Service, tsaService *tsa.Service, logger *slog.Logger) (*Server, error) {
	if data == nil || authService == nil || pkiService == nil || tsaService == nil {
		return nil, errors.New("HTTP API dependencies are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{config: cfg, store: data, auth: authService, pki: pkiService, tsa: tsaService,
		logger: logger, console: http.NewServeMux(), public: http.NewServeMux(), rates: make(map[string]rateWindow), cryptoSlots: make(chan struct{}, 4)}
	registry := prometheus.NewRegistry()
	s.requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pki_console_http_requests_total",
		Help: "PKI-Console HTTP requests by method, route, and status."}, []string{"method", "route", "status"})
	s.requestLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "pki_console_http_request_duration_seconds",
		Help: "PKI-Console HTTP request duration by method and route.", Buckets: prometheus.DefBuckets}, []string{"method", "route"})
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		s.requestCount, s.requestLatency)
	s.metricsHandler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	application := http.HandlerFunc(s.dispatch)
	return s.recoverPanic(s.securityHeaders(s.requestLog(application)))
}

func (s *Server) routes() {
	s.console.Handle("POST /api/v1/auth/login", s.limitExpensive(http.HandlerFunc(s.login)))
	s.console.Handle("POST /api/v1/auth/logout", s.requireAuth(http.HandlerFunc(s.logout)))
	s.console.Handle("GET /api/v1/auth/session", s.requireAuth(http.HandlerFunc(s.session)))
	s.console.Handle("GET /api/v1/users", s.requireAuth(http.HandlerFunc(s.listUsers)))
	s.console.Handle("POST /api/v1/users", s.requireAuth(s.idempotent(http.HandlerFunc(s.createUser))))
	s.console.Handle("PATCH /api/v1/users/{id}/status", s.requireAuth(s.idempotent(http.HandlerFunc(s.setUserStatus))))
	s.console.Handle("PUT /api/v1/users/{id}/password", s.requireAuth(s.idempotent(http.HandlerFunc(s.resetUserPassword))))
	s.console.Handle("GET /api/v1/cas/{id}/grants", s.requireAuth(http.HandlerFunc(s.listGrants)))
	s.console.Handle("POST /api/v1/cas/{id}/grants", s.requireAuth(s.idempotent(http.HandlerFunc(s.createGrant))))
	s.console.Handle("DELETE /api/v1/cas/{id}/grants/{userID}/{permission}", s.requireAuth(s.idempotent(http.HandlerFunc(s.deleteGrant))))
	s.console.Handle("GET /api/v1/cas", s.requireAuth(http.HandlerFunc(s.listCAs)))
	s.console.Handle("POST /api/v1/cas/roots", s.requireAuth(s.idempotent(http.HandlerFunc(s.createRoot))))
	s.console.Handle("POST /api/v1/cas/intermediates", s.requireAuth(s.idempotent(http.HandlerFunc(s.createIntermediate))))
	s.console.Handle("POST /api/v1/cas/import", s.requireAuth(s.idempotent(http.HandlerFunc(s.importCA))))
	s.console.Handle("GET /api/v1/cas/{id}", s.requireAuth(http.HandlerFunc(s.getCA)))
	s.console.Handle("POST /api/v1/cas/{id}/keys/export", s.requireAuth(http.HandlerFunc(s.exportCAKey)))
	s.console.Handle("GET /api/v1/cas/{id}/profiles", s.requireAuth(http.HandlerFunc(s.listProfiles)))
	s.console.Handle("POST /api/v1/cas/{id}/profiles", s.requireAuth(s.idempotent(http.HandlerFunc(s.createProfile))))
	s.console.Handle("PUT /api/v1/cas/{id}/profiles/{profileID}", s.requireAuth(s.idempotent(http.HandlerFunc(s.updateProfile))))
	s.console.Handle("DELETE /api/v1/cas/{id}/profiles/{profileID}", s.requireAuth(s.idempotent(http.HandlerFunc(s.deleteProfile))))
	s.console.Handle("GET /api/v1/cas/{id}/timestamp-authorities", s.requireAuth(http.HandlerFunc(s.listTimestampAuthorities)))
	s.console.Handle("POST /api/v1/cas/{id}/timestamp-authorities", s.requireAuth(s.idempotent(http.HandlerFunc(s.createTimestampAuthority))))
	s.console.Handle("POST /api/v1/certificate-requests", s.requireAuth(s.idempotent(http.HandlerFunc(s.createCertificateRequest))))
	s.console.Handle("GET /api/v1/certificate-requests", s.requireAuth(http.HandlerFunc(s.listCertificateRequests)))
	s.console.Handle("GET /api/v1/certificate-requests/{id}", s.requireAuth(http.HandlerFunc(s.getCertificateRequest)))
	s.console.Handle("POST /api/v1/certificate-requests/{id}/approve", s.requireAuth(s.idempotent(http.HandlerFunc(s.approveCertificateRequest))))
	s.console.Handle("POST /api/v1/certificate-requests/{id}/reject", s.requireAuth(s.idempotent(http.HandlerFunc(s.rejectCertificateRequest))))
	s.console.Handle("GET /api/v1/certificate-inventory", s.requireAuth(http.HandlerFunc(s.listCertificateInventory)))
	s.console.Handle("GET /api/v1/certificates", s.requireAuth(http.HandlerFunc(s.listCertificates)))
	s.console.Handle("GET /api/v1/certificates/{id}", s.requireAuth(http.HandlerFunc(s.getCertificate)))
	s.console.Handle("GET /api/v1/certificates/{id}/download", s.requireAuth(http.HandlerFunc(s.downloadCertificate)))
	s.console.Handle("POST /api/v1/certificates/{id}/revoke", s.requireAuth(s.idempotent(http.HandlerFunc(s.revokeCertificate))))
	s.console.Handle("POST /api/v1/certificates/{id}/private-key/download", s.requireAuth(http.HandlerFunc(s.downloadPrivateKey)))
	s.console.Handle("POST /api/v1/utilities/certinfo", s.requireAuth(http.HandlerFunc(s.certInfo)))
	s.console.Handle("POST /api/v1/utilities/csr", s.requireAuth(http.HandlerFunc(s.generateCSR)))
	s.console.Handle("POST /api/v1/utilities/bundle", s.requireAuth(http.HandlerFunc(s.bundleCertificates)))
	s.console.Handle("GET /api/v1/audit-events", s.requireAuth(http.HandlerFunc(s.listAuditEvents)))
	s.console.Handle("GET /api/v1/metrics", s.requireAuth(http.HandlerFunc(s.metrics)))
	s.console.Handle("GET /api/v1/health/live", http.HandlerFunc(s.live))
	s.console.Handle("GET /api/v1/health/ready", http.HandlerFunc(s.ready))
	s.console.Handle("GET /api/v1/version", http.HandlerFunc(s.version))

	s.public.HandleFunc("GET /pki/v1/authorities", s.publicAuthorities)
	s.public.HandleFunc("GET /pki/v1/certificates/by-fingerprint/{fingerprint}", s.publicCertificateByFingerprint)
	s.public.HandleFunc("GET /pki/v1/certificates/by-issuer/{issuer}/serial/{serial}", s.publicCertificateBySerial)
	s.public.HandleFunc("GET /pki/v1/status/{issuer}/{serial}", s.publicCertificateStatus)
	s.public.HandleFunc("GET /issuers/{file}", s.publicIssuer)
	s.public.Handle("GET /crl/{file}", s.limitExpensive(http.HandlerFunc(s.publicCRL)))
	s.public.Handle("POST /ocsp/{slug}", s.limitExpensive(http.HandlerFunc(s.publicOCSP)))
	s.public.Handle("GET /ocsp/{slug}/{request...}", s.limitExpensive(http.HandlerFunc(s.publicOCSP)))
	s.public.Handle("POST /tsa/{slug}", s.limitExpensive(http.HandlerFunc(s.publicTimestamp)))
	s.public.HandleFunc("GET /health/live", s.live)
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case strings.ToLower(s.config.ConsoleHostname):
		origin := s.config.ConsoleBaseURL.Scheme + "://" + s.config.ConsoleBaseURL.Host
		if requestOrigin := r.Header.Get("Origin"); requestOrigin != "" {
			if requestOrigin != origin {
				problem(w, http.StatusForbidden, "origin_not_allowed", "Request origin is not allowed")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,X-CSRF-Token,Idempotency-Key")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		serveSurface(w, r, s.console, s.consoleFrontend)
	case strings.ToLower(s.config.PublicHostname):
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		serveSurface(w, r, s.public, s.publicFrontend)
	default:
		problem(w, http.StatusMisdirectedRequest, "unknown_host", "Request hostname is not configured")
	}
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.cookieName())
		if err != nil {
			problem(w, http.StatusUnauthorized, "authentication_required", "Authentication is required")
			return
		}
		principal, err := s.auth.Authenticate(r.Context(), cookie.Value, r.Header.Get("X-CSRF-Token"),
			r.Method)
		if err != nil {
			problem(w, http.StatusUnauthorized, "authentication_failed", "Session or CSRF verification failed")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			mutation := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := s.audit(r, "http.mutation.authenticated", "http_request", nil, "success", map[string]string{"method": r.Method, "path": r.URL.Path}); err != nil {
					problem(w, http.StatusServiceUnavailable, "audit_unavailable", "Audit storage is unavailable")
					return
				}
				next.ServeHTTP(w, r)
			})
			if r.URL.Path == "/api/v1/auth/logout" {
				mutation.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			s.limitExpensive(mutation).ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *bufferedResponse) Header() http.Header { return w.header }
func (w *bufferedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *bufferedResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(body)
}

func (s *Server) idempotent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if len(key) < 8 || len(key) > 128 {
			problem(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must contain 8-128 characters")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			problem(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds one MiB")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		digest := sha256.Sum256(append([]byte(r.Method+"\n"+r.URL.RequestURI()+"\n"), body...))
		scope := r.Method + " " + r.URL.Path
		userID := principal(r).User.ID
		stored, claimed, err := s.store.ClaimIdempotency(r.Context(), userID, scope, key, digest[:])
		if err != nil {
			status := http.StatusConflict
			code := "idempotency_conflict"
			if !errors.Is(err, store.ErrIdempotencyConflict) {
				status, code = http.StatusInternalServerError, "database_error"
			}
			problem(w, status, code, "Idempotent request conflicts with another request or is still in progress")
			return
		}
		if !claimed && stored.Ready {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Idempotency-Replayed", "true")
			w.WriteHeader(stored.ResponseCode)
			_, _ = w.Write(stored.ResponseBody)
			return
		}
		buffered := &bufferedResponse{header: make(http.Header)}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.store.AbortIdempotency(r.Context(), userID, scope, key, digest[:])
				panic(recovered)
			}
		}()
		next.ServeHTTP(buffered, r)
		if buffered.status == 0 {
			buffered.status = http.StatusOK
		}
		if buffered.status >= 500 {
			s.store.AbortIdempotency(r.Context(), userID, scope, key, digest[:])
		} else if err := s.store.CompleteIdempotency(r.Context(), userID, scope, key, digest[:], buffered.status, buffered.body.Bytes()); err != nil {
			s.store.AbortIdempotency(r.Context(), userID, scope, key, digest[:])
			problem(w, http.StatusInternalServerError, "idempotency_storage_failed", "Unable to persist idempotent response")
			return
		}
		for name, values := range buffered.header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.Header().Set("Idempotency-Replayed", "false")
		w.WriteHeader(buffered.status)
		_, _ = w.Write(buffered.body.Bytes())
	})
}

func (s *Server) cookieName() string {
	if s.config.DevelopmentInsecure {
		return auth.DevelopmentCookieName
	}
	return auth.CookieName
}

func principal(r *http.Request) auth.Principal {
	value, _ := r.Context().Value(principalKey).(auth.Principal)
	return value
}

func requestID(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey).(string)
	return value
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 {
			var raw [16]byte
			_, _ = rand.Read(raw[:])
			id = hex.EncodeToString(raw[:])
		}
		w.Header().Set("X-Request-ID", id)
		deadlineCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		ctx := context.WithValue(deadlineCtx, requestIDKey, id)
		recorder := &statusResponseWriter{ResponseWriter: w}
		loggedRequest := r.WithContext(ctx)
		next.ServeHTTP(recorder, loggedRequest)
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		route := loggedRequest.Pattern
		if route == "" {
			route = "unmatched"
		}
		method := metricMethod(r.Method)
		s.requestCount.WithLabelValues(method, route, strconv.Itoa(recorder.status)).Inc()
		s.requestLatency.WithLabelValues(method, route).Observe(time.Since(started).Seconds())
		s.logger.Info("http request", "request_id", id, "method", r.Method,
			"path", r.URL.Path, "host", r.Host, "status", recorder.status,
			"response_bytes", recorder.bytes, "duration_ms", time.Since(started).Milliseconds())
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	written, err := w.ResponseWriter.Write(body)
	w.bytes += written
	return written, err
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("request panic", "request_id", requestID(r), "error", fmt.Sprint(recovered))
				problem(w, http.StatusInternalServerError, "internal_error", "Internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		problem(w, http.StatusBadRequest, "invalid_json", "Request body is not valid for this endpoint")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		problem(w, http.StatusBadRequest, "invalid_json", "Request body must contain one JSON document")
		return false
	}
	return true
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role == "user" {
		problem(w, http.StatusForbidden, "forbidden", "Metrics require an operator or super administrator")
		return
	}
	s.metricsHandler.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func problem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":  "https://pki-console.invalid/problems/" + code,
		"title": http.StatusText(status), "status": status, "detail": detail, "code": code,
	})
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	if s.isTrustedProxy(r.RemoteAddr) {
		hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		// Walk from the direct proxy towards the client. An incoming attacker
		// prefix must not win when Nginx appends the real source address.
		for i := len(hops) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(hops[i]))
			if ip == nil {
				return host
			}
			if !s.isTrustedIP(ip) || i == 0 {
				return ip.String()
			}
		}
	}
	return host
}

func (s *Server) isTrustedProxy(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return false
	}
	remote := net.ParseIP(host)
	return s.isTrustedIP(remote)
}

func (s *Server) isTrustedIP(remote net.IP) bool {
	for _, rawNetwork := range s.config.TrustedProxyCIDRs {
		_, network, parseErr := net.ParseCIDR(rawNetwork)
		if parseErr == nil && remote != nil && network.Contains(remote) {
			return true
		}
	}
	return false
}

func (s *Server) allowRequest(key string, limit int, window time.Duration) (bool, time.Duration) {
	now := time.Now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if !s.rateSweep.After(now) {
		for item, value := range s.rates {
			if !value.Reset.After(now) {
				delete(s.rates, item)
			}
		}
		s.rateSweep = now.Add(time.Second)
	}
	current := s.rates[key]
	if !current.Reset.After(now) {
		if _, exists := s.rates[key]; !exists && len(s.rates) >= 4096 {
			return false, time.Second
		}
		current.Count = 0
		current.Reset = now.Add(window)
	}
	if current.Count >= limit {
		return false, time.Until(current.Reset)
	}
	current.Count++
	s.rates[key] = current
	return true, 0
}

func (s *Server) limitExpensive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.cryptoSlots <- struct{}{}:
			defer func() { <-s.cryptoSlots }()
			next.ServeHTTP(w, r)
		default:
			rateLimited(w, time.Second)
		}
	})
}

func metricMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return method
	default:
		return "OTHER"
	}
}

func rateLimited(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
	problem(w, http.StatusTooManyRequests, "rate_limited", "Too many requests; retry later")
}

func (s *Server) audit(r *http.Request, action, resourceType string, resourceID *string, outcome string, metadata any) error {
	p := principal(r)
	var actorID, role, sessionID *string
	if p.User.ID != "" {
		actorID, role, sessionID = &p.User.ID, &p.User.Role, &p.SessionID
	}
	ip := s.clientIP(r)
	if err := s.store.Audit(r.Context(), store.AuditEvent{ActorUserID: actorID, ActorRole: role,
		SessionID: sessionID, Action: action, ResourceType: resourceType, ResourceID: resourceID,
		Outcome: outcome, RequestID: requestID(r), SourceIP: &ip, UserAgent: r.UserAgent(),
		Metadata: metadata}); err != nil {
		s.logger.Error("write audit event", "request_id", requestID(r), "error", err)
		return err
	}
	return nil
}
