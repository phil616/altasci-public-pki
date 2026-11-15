// Package signing implements isolated, bearer-authorized PKCS#10 issuance.
// It does not import the managed PKI service or reference its CA/certificate tables.
package signing

import "time"

type Policy struct {
	Version                int      `json:"version"`
	AllowedDNSNames        []string `json:"allowed_dns_names" jsonnull:"empty"`
	AllowedIPRanges        []string `json:"allowed_ip_ranges" jsonnull:"empty"`
	AllowedEmailDomains    []string `json:"allowed_email_domains" jsonnull:"empty"`
	AllowedURIPrefixes     []string `json:"allowed_uri_prefixes" jsonnull:"empty"`
	AllowWildcards         bool     `json:"allow_wildcards"`
	ExtendedKeyUsages      []string `json:"extended_key_usages"`
	DefaultValiditySeconds int64    `json:"default_validity_seconds"`
	MaxValiditySeconds     int64    `json:"max_validity_seconds"`
	MaxSANs                int      `json:"max_sans"`
}

type Instance struct {
	ID                string    `json:"id"`
	OwnerID           string    `json:"owner_id"`
	Name              string    `json:"name"`
	CertificatePEM    string    `json:"certificate_pem"`
	ChainPEM          string    `json:"chain_pem"`
	Policy            Policy    `json:"policy"`
	Enabled           bool      `json:"enabled"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	Endpoint          string    `json:"endpoint"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	ciphertext, nonce []byte
	kekID             string
}

type Credential struct {
	ID            string     `json:"id"`
	InstanceID    string     `json:"instance_id"`
	Name          string     `json:"name"`
	Scopes        []string   `json:"scopes"`
	Policy        *Policy    `json:"policy"`
	MaxIssuances  int        `json:"max_issuances"`
	IssuedCount   int        `json:"issued_count"`
	RatePerMinute int        `json:"rate_per_minute"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
	CreatedAt     time.Time  `json:"created_at"`
	tokenHash     []byte
	rateWindow    time.Time
	rateCount     int
}

type Certificate struct {
	ID                string     `json:"id"`
	InstanceID        string     `json:"instance_id"`
	CredentialID      string     `json:"credential_id"`
	Serial            string     `json:"serial"`
	CertificatePEM    string     `json:"certificate_pem"`
	ChainPEM          string     `json:"chain_pem"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	NotBefore         time.Time  `json:"not_before"`
	NotAfter          time.Time  `json:"not_after"`
	RevokedAt         *time.Time `json:"revoked_at"`
	RevocationReason  *int       `json:"revocation_reason"`
	CreatedAt         time.Time  `json:"created_at"`
	Status            string     `json:"status"`
}

type CreateInput struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	ChainPEM       string `json:"chain_pem"`
	Policy         Policy `json:"policy"`
}

type UpdateInput struct {
	Name    string `json:"name"`
	Policy  Policy `json:"policy"`
	Enabled bool   `json:"enabled"`
}

type CredentialInput struct {
	Name            string   `json:"name"`
	Scopes          []string `json:"scopes"`
	Policy          *Policy  `json:"policy"`
	LifetimeSeconds int64    `json:"lifetime_seconds"`
	MaxIssuances    int      `json:"max_issuances"`
	RatePerMinute   int      `json:"rate_per_minute"`
}

type IssueInput struct {
	CSRPEM          string `json:"csr_pem"`
	ValiditySeconds int64  `json:"validity_seconds"`
}

type RevokeInput struct {
	Reason int `json:"reason"`
}

type Error struct {
	Status       int
	Code, Detail string
}

func (e *Error) Error() string    { return e.Code + ": " + e.Detail }
func invalid(detail string) error { return &Error{422, "signing_policy_rejected", detail} }
func denied() error {
	return &Error{401, "signing_unauthorized", "Credential is invalid, expired, revoked or not permitted"}
}
func missing() error { return &Error{404, "signing_not_found", "Signing resource was not found"} }
