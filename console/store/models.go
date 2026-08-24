package store

import (
	"encoding/json"
	"time"
)

type User struct {
	ID               string     `json:"id"`
	Username         string     `json:"username"`
	Email            *string    `json:"email,omitempty"`
	Role             string     `json:"role"`
	PasswordHash     string     `json:"-"`
	Status           string     `json:"status"`
	FailedLoginCount int        `json:"-"`
	LockedUntil      *time.Time `json:"-"`
	TOTPLastStep     int64      `json:"-"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type Session struct {
	ID                string
	User              User
	CSRFHash          []byte
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	CreatedAt         time.Time
	LastSeenAt        time.Time
}

type CertificateAuthority struct {
	ID             string          `json:"id"`
	ParentCAID     *string         `json:"parent_ca_id,omitempty"`
	Slug           string          `json:"slug"`
	Name           string          `json:"name"`
	Kind           string          `json:"kind"`
	Status         string          `json:"status"`
	Subject        json.RawMessage `json:"subject"`
	Serial         string          `json:"serial"`
	SKI            []byte          `json:"-"`
	AKI            []byte          `json:"-"`
	CertificatePEM string          `json:"certificate_pem"`
	ChainPEM       string          `json:"chain_pem"`
	NotBefore      time.Time       `json:"not_before"`
	NotAfter       time.Time       `json:"not_after"`
	PathLength     int             `json:"path_length"`
	CRLURL         *string         `json:"crl_url,omitempty"`
	OCSPURL        *string         `json:"ocsp_url,omitempty"`
	IssuerURL      *string         `json:"issuer_url,omitempty"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
}

type CAKeyVersion struct {
	ID                   string
	CAID                 string
	Version              int
	Algorithm            string
	PublicKeyFingerprint []byte
	EncryptedPKCS8       []byte
	Nonce                []byte
	KEKID                string
	Status               string
}

type CAGrant struct {
	CAID       string    `json:"ca_id"`
	UserID     string    `json:"user_id"`
	Permission string    `json:"permission"`
	GrantedBy  string    `json:"granted_by"`
	CreatedAt  time.Time `json:"created_at"`
}

type OCSPResponder struct {
	ID             string
	CAID           string
	CertificatePEM string
	EncryptedPKCS8 []byte
	Nonce          []byte
	KEKID          string
	NotBefore      time.Time
	NotAfter       time.Time
	Status         string
}

type SigningProfile struct {
	ID                 string          `json:"id"`
	CAID               string          `json:"ca_id"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	DefaultValidity    time.Duration   `json:"default_validity_seconds"`
	MaxValidity        time.Duration   `json:"max_validity_seconds"`
	KeyUsages          []string        `json:"key_usages"`
	ExtendedKeyUsages  []string        `json:"extended_key_usages"`
	AllowedDNSPatterns []string        `json:"allowed_dns_patterns"`
	AllowedIPRanges    []string        `json:"allowed_ip_ranges"`
	AllowEmailSANs     bool            `json:"allow_email_sans"`
	AllowURISANs       bool            `json:"allow_uri_sans"`
	Policy             json.RawMessage `json:"policy"`
	Enabled            bool            `json:"enabled"`
}

func (profile SigningProfile) MarshalJSON() ([]byte, error) {
	type response struct {
		ID                     string          `json:"id"`
		CAID                   string          `json:"ca_id"`
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
	return json.Marshal(response{ID: profile.ID, CAID: profile.CAID, Name: profile.Name,
		Description: profile.Description, DefaultValiditySeconds: int64(profile.DefaultValidity.Seconds()),
		MaxValiditySeconds: int64(profile.MaxValidity.Seconds()), KeyUsages: profile.KeyUsages,
		ExtendedKeyUsages: profile.ExtendedKeyUsages, AllowedDNSPatterns: profile.AllowedDNSPatterns,
		AllowedIPRanges: profile.AllowedIPRanges, AllowEmailSANs: profile.AllowEmailSANs,
		AllowURISANs: profile.AllowURISANs, Policy: profile.Policy, Enabled: profile.Enabled})
}

type CertificateRequest struct {
	ID                    string          `json:"id"`
	RequesterID           string          `json:"requester_id"`
	CAID                  string          `json:"ca_id"`
	ProfileID             string          `json:"profile_id"`
	CSRPEM                *string         `json:"csr_pem,omitempty"`
	RequestedSubject      json.RawMessage `json:"requested_subject"`
	RequestedSANs         json.RawMessage `json:"requested_sans"`
	KeyGenerationMode     string          `json:"key_generation_mode"`
	RequestedValiditySecs *int64          `json:"requested_validity_seconds,omitempty"`
	Status                string          `json:"status"`
	RejectionReason       *string         `json:"rejection_reason,omitempty"`
	ErrorCode             *string         `json:"error_code,omitempty"`
	SubmittedAt           time.Time       `json:"submitted_at"`
	ApprovedAt            *time.Time      `json:"approved_at,omitempty"`
	IssuedAt              *time.Time      `json:"issued_at,omitempty"`
}

type Certificate struct {
	ID                string          `json:"id"`
	IssuerCAID        string          `json:"issuer_ca_id"`
	OwnerUserID       string          `json:"owner_user_id"`
	RequestID         *string         `json:"request_id,omitempty"`
	Serial            string          `json:"serial"`
	AKI               []byte          `json:"-"`
	SKI               []byte          `json:"-"`
	FingerprintSHA256 []byte          `json:"-"`
	CertificatePEM    string          `json:"certificate_pem"`
	ChainPEM          string          `json:"chain_pem"`
	Subject           json.RawMessage `json:"subject"`
	SANs              json.RawMessage `json:"sans"`
	NotBefore         time.Time       `json:"not_before"`
	NotAfter          time.Time       `json:"not_after"`
	Status            string          `json:"status"`
	CreatedAt         time.Time       `json:"created_at"`
}

// CertificateInventoryItem combines the request workflow and the resulting
// certificate so Console users can follow an application from submission to
// issuance without switching between unrelated lists.
type CertificateInventoryItem struct {
	RequestID         *string         `json:"request_id,omitempty"`
	CertificateID     *string         `json:"certificate_id,omitempty"`
	OwnerUserID       string          `json:"owner_user_id"`
	RequesterUsername string          `json:"requester_username"`
	IssuerCAID        string          `json:"issuer_ca_id"`
	IssuerName        string          `json:"issuer_name"`
	IssuerSlug        string          `json:"issuer_slug"`
	Subject           json.RawMessage `json:"subject"`
	SANs              json.RawMessage `json:"sans"`
	WorkflowStatus    string          `json:"workflow_status"`
	RequestStatus     *string         `json:"request_status,omitempty"`
	CertificateStatus *string         `json:"certificate_status,omitempty"`
	Serial            *string         `json:"serial,omitempty"`
	RejectionReason   *string         `json:"rejection_reason,omitempty"`
	ErrorCode         *string         `json:"error_code,omitempty"`
	ApproverID        *string         `json:"approver_id,omitempty"`
	ApproverUsername  *string         `json:"approver_username,omitempty"`
	SubmittedAt       time.Time       `json:"submitted_at"`
	ApprovedAt        *time.Time      `json:"approved_at,omitempty"`
	IssuedAt          *time.Time      `json:"issued_at,omitempty"`
	NotBefore         *time.Time      `json:"not_before,omitempty"`
	NotAfter          *time.Time      `json:"not_after,omitempty"`
}

type AuditEvent struct {
	ActorUserID  *string
	ActorRole    *string
	SessionID    *string
	Action       string
	ResourceType string
	ResourceID   *string
	Outcome      string
	RequestID    string
	SourceIP     *string
	UserAgent    string
	AccessSub    *string
	BeforeState  any
	AfterState   any
	Metadata     any
}

type AuditRecord struct {
	ID           string          `json:"id"`
	ActorUserID  *string         `json:"actor_user_id,omitempty"`
	ActorRole    *string         `json:"actor_role,omitempty"`
	SessionID    *string         `json:"session_id,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	Outcome      string          `json:"outcome"`
	RequestID    string          `json:"request_id"`
	SourceIP     *string         `json:"source_ip,omitempty"`
	UserAgent    string          `json:"user_agent"`
	AccessSub    *string         `json:"cf_access_sub,omitempty"`
	BeforeState  json.RawMessage `json:"before_state,omitempty"`
	AfterState   json.RawMessage `json:"after_state,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	PreviousHash string          `json:"previous_hash"`
	EventHash    string          `json:"event_hash"`
	OccurredAt   time.Time       `json:"occurred_at"`
}
