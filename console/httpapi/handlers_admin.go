package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/bundler"
	cfconfig "github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/csr"
)

type profileInput struct {
	Name                   string          `json:"name"`
	Description            string          `json:"description"`
	DefaultValiditySeconds int64           `json:"default_validity_seconds"`
	MaxValiditySeconds     int64           `json:"max_validity_seconds"`
	KeyUsages              []string        `json:"key_usages"`
	ExtendedKeyUsages      []string        `json:"extended_key_usages"`
	AllowedDNSPatterns     []string        `json:"allowed_dns_patterns"`
	AllowedIPRanges        []string        `json:"allowed_ip_ranges"`
	AllowEmailSANs         bool            `json:"allow_email_sans"`
	AllowURISANs           bool            `json:"allow_uri_sans"`
	Policy                 json.RawMessage `json:"policy"`
	Enabled                bool            `json:"enabled"`
}

func (input profileInput) validateSeconds() error {
	const maximum = int64(397 * 24 * 60 * 60)
	if input.DefaultValiditySeconds <= 0 || input.DefaultValiditySeconds > maximum ||
		input.MaxValiditySeconds < input.DefaultValiditySeconds || input.MaxValiditySeconds > maximum {
		return errors.New("validity must be between one second and 397 days")
	}
	return nil
}

func (input profileInput) profile(caID, id string) store.SigningProfile {
	return store.SigningProfile{ID: id, CAID: caID, Name: strings.TrimSpace(input.Name),
		Description:     strings.TrimSpace(input.Description),
		DefaultValidity: time.Duration(input.DefaultValiditySeconds) * time.Second,
		MaxValidity:     time.Duration(input.MaxValiditySeconds) * time.Second,
		KeyUsages:       append([]string{}, input.KeyUsages...), ExtendedKeyUsages: append([]string{}, input.ExtendedKeyUsages...),
		AllowedDNSPatterns: append([]string{}, input.AllowedDNSPatterns...), AllowedIPRanges: append([]string{}, input.AllowedIPRanges...),
		AllowEmailSANs: input.AllowEmailSANs, AllowURISANs: input.AllowURISANs,
		Policy: input.Policy, Enabled: input.Enabled}
}

func validateProfile(profile store.SigningProfile) error {
	if profile.Name == "" || len(profile.Name) > 128 || profile.DefaultValidity <= 0 ||
		profile.MaxValidity < profile.DefaultValidity || profile.MaxValidity > 397*24*time.Hour {
		return errors.New("name and validity limits are invalid")
	}
	if len(profile.KeyUsages) == 0 {
		return errors.New("at least one key usage is required")
	}
	for _, usage := range profile.KeyUsages {
		if _, ok := cfconfig.KeyUsage[usage]; !ok || usage == "cert sign" || usage == "crl sign" {
			return errors.New("key usage is not valid for leaf certificates")
		}
	}
	for _, usage := range profile.ExtendedKeyUsages {
		if _, ok := cfconfig.ExtKeyUsage[usage]; !ok || usage == "ocsp signing" {
			return errors.New("extended key usage is not valid for leaf certificates")
		}
	}
	for _, pattern := range profile.AllowedDNSPatterns {
		if len(pattern) > 255 {
			return errors.New("DNS pattern is too long")
		}
		if _, err := path.Match(pattern, "validation.example"); err != nil {
			return errors.New("DNS pattern is not a valid glob expression")
		}
	}
	for _, network := range profile.AllowedIPRanges {
		if _, _, err := net.ParseCIDR(network); err != nil {
			return errors.New("allowed IP range is invalid")
		}
	}
	if len(profile.Policy) != 0 && !json.Valid(profile.Policy) {
		return errors.New("policy must be valid JSON")
	}
	return nil
}

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.store.ListProfiles(r.Context(), r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to list signing profiles")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": profiles})
}

func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can create signing profiles")
		return
	}
	var input profileInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := input.validateSeconds(); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_signing_profile", err.Error())
		return
	}
	profile := input.profile(r.PathValue("id"), "")
	if err := validateProfile(profile); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_signing_profile", err.Error())
		return
	}
	created, err := s.store.CreateProfile(r.Context(), profile)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "profile_creation_failed", "Unable to create signing profile")
		return
	}
	_ = s.audit(r, "signing_profile.create", "signing_profile", &created.ID, "success", nil)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can update signing profiles")
		return
	}
	var input profileInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := input.validateSeconds(); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_signing_profile", err.Error())
		return
	}
	profile := input.profile(r.PathValue("id"), r.PathValue("profileID"))
	if err := validateProfile(profile); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_signing_profile", err.Error())
		return
	}
	updated, err := s.store.UpdateProfile(r.Context(), profile)
	if err != nil {
		problem(w, http.StatusNotFound, "profile_not_found", "Signing profile was not found")
		return
	}
	_ = s.audit(r, "signing_profile.update", "signing_profile", &updated.ID, "success", nil)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can delete signing profiles")
		return
	}
	id := r.PathValue("profileID")
	if err := s.store.DeleteProfile(r.Context(), r.PathValue("id"), id); err != nil {
		problem(w, http.StatusConflict, "profile_delete_failed", "Default or referenced profiles cannot be deleted")
		return
	}
	_ = s.audit(r, "signing_profile.delete", "signing_profile", &id, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if principal(r).User.Role != "super_admin" {
		problem(w, http.StatusForbidden, "forbidden", "Only the super administrator can read audit events")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database_error", "Unable to read audit events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events})
}

func (s *Server) generateCSR(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Subject   pki.Subject `json:"subject"`
		SANs      []string    `json:"sans"`
		Algorithm string      `json:"algorithm"`
		KeySize   int         `json:"key_size"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	keyRequest := &csr.KeyRequest{A: strings.ToLower(input.Algorithm), S: input.KeySize}
	if keyRequest.A == "" {
		keyRequest.A, keyRequest.S = "rsa", 3072
	}
	if (keyRequest.A != "rsa" || (keyRequest.S != 3072 && keyRequest.S != 4096)) &&
		(keyRequest.A != "ecdsa" || (keyRequest.S != 256 && keyRequest.S != 384)) {
		problem(w, http.StatusUnprocessableEntity, "invalid_key_parameters", "Use RSA-3072/4096 or ECDSA P-256/P-384")
		return
	}
	request := &csr.CertificateRequest{CN: input.Subject.CommonName, Hosts: input.SANs,
		Names: []csr.Name{{C: input.Subject.Country, ST: input.Subject.Province, L: input.Subject.Locality,
			O: input.Subject.Organization, OU: input.Subject.OrganizationalUnit}}, KeyRequest: keyRequest}
	csrPEM, keyPEM, err := csr.ParseRequest(request)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "csr_generation_failed", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	_ = s.audit(r, "utility.csr.generate", "utility", nil, "success", map[string]any{"algorithm": keyRequest.A, "size": keyRequest.S})
	writeJSON(w, http.StatusOK, map[string]string{"csr_pem": string(csrPEM), "private_key_pem": string(keyPEM)})
}

func (s *Server) bundleCertificates(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CertificatesPEM  string `json:"certificates_pem"`
		RootsPEM         string `json:"roots_pem"`
		IntermediatesPEM string `json:"intermediates_pem"`
		Flavor           string `json:"flavor"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	flavor := bundler.BundleFlavor(strings.ToLower(input.Flavor))
	if flavor == "" {
		flavor = bundler.Optimal
	}
	if flavor != bundler.Optimal && flavor != bundler.Ubiquitous && flavor != bundler.Force {
		problem(w, http.StatusUnprocessableEntity, "invalid_bundle_flavor", "Flavor must be optimal, ubiquitous, or force")
		return
	}
	var roots []byte
	if input.RootsPEM != "" {
		roots = []byte(input.RootsPEM)
	}
	b, err := bundler.NewBundlerFromPEM(roots, []byte(input.IntermediatesPEM), bundler.WithoutAIAFetching())
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_bundle_roots", err.Error())
		return
	}
	bundle, err := b.BundleFromPEMorDER([]byte(input.CertificatesPEM), nil, flavor, "")
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "bundle_failed", err.Error())
		return
	}
	_ = s.audit(r, "utility.bundle", "utility", nil, "success", map[string]string{"flavor": string(flavor)})
	writeJSON(w, http.StatusOK, bundle)
}
