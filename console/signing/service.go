package signing

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool *pgxpool.Pool
	keys security.Keyring
	base string
	now  func() time.Time
}
type RequestInfo struct{ RequestID, IP, UserAgent string }

func New(pool *pgxpool.Pool, keys security.Keyring, publicBase string) *Service {
	return &Service{pool: pool, keys: keys, base: strings.TrimRight(publicBase, "/"), now: time.Now}
}
func validID(value string) bool {
	var id pgtype.UUID
	return id.Scan(value) == nil && id.Valid && id.Bytes != [16]byte{}
}
func validateName(value string) error {
	if len(strings.TrimSpace(value)) == 0 || len(value) > 128 || strings.ContainsFunc(value, unicode.IsControl) {
		return invalid("Name must contain 1..128 bytes without control characters")
	}
	return nil
}

const instanceColumns = `id::text,owner_id::text,name,certificate_pem,chain_pem,encrypted_key,key_nonce,kek_id,policy,enabled,created_at,updated_at`

// #nosec G101 -- SQL column names only; credential secrets are generated with crypto/rand.
const credentialColumns = `id::text,instance_id::text,name,token_hash,scopes,policy,max_issuances,issued_count,rate_per_minute,rate_window,rate_count,expires_at,revoked_at,created_at`
const certificateColumns = `id::text,instance_id::text,credential_id::text,serial::text,certificate_pem,chain_pem,fingerprint_sha256,not_before,not_after,revoked_at,revocation_reason,created_at`

func (s *Service) scanInstance(row pgx.Row) (Instance, error) {
	var i Instance
	var policy []byte
	err := row.Scan(&i.ID, &i.OwnerID, &i.Name, &i.CertificatePEM, &i.ChainPEM, &i.ciphertext, &i.nonce, &i.kekID, &policy, &i.Enabled, &i.CreatedAt, &i.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return i, missing()
	}
	if err != nil {
		return i, err
	}
	if err = json.Unmarshal(policy, &i.Policy); err != nil {
		return i, err
	}
	block, _ := pem.Decode([]byte(i.CertificatePEM))
	if block == nil {
		return i, errors.New("invalid stored signing CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return i, err
	}
	i.NotBefore, i.NotAfter = cert.NotBefore, cert.NotAfter
	i.Endpoint = s.base + "/signing/" + i.ID + "/issue"
	return i, nil
}
func scanCredential(row pgx.Row) (Credential, error) {
	var c Credential
	var policy []byte
	err := row.Scan(&c.ID, &c.InstanceID, &c.Name, &c.tokenHash, &c.Scopes, &policy, &c.MaxIssuances, &c.IssuedCount, &c.RatePerMinute, &c.rateWindow, &c.rateCount, &c.ExpiresAt, &c.RevokedAt, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, missing()
	}
	if err != nil {
		return c, err
	}
	if len(policy) > 0 && string(policy) != "null" {
		c.Policy = &Policy{}
		err = json.Unmarshal(policy, c.Policy)
	}
	return c, err
}
func (s *Service) scanCertificate(row pgx.Row) (Certificate, error) {
	var c Certificate
	err := row.Scan(&c.ID, &c.InstanceID, &c.CredentialID, &c.Serial, &c.CertificatePEM, &c.ChainPEM, &c.FingerprintSHA256, &c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.RevocationReason, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, missing()
	}
	c.Status = "good"
	if c.RevokedAt != nil {
		c.Status = "revoked"
	} else if !s.now().Before(c.NotAfter) {
		c.Status = "expired"
	}
	return c, err
}

func (s *Service) audit(ctx context.Context, tx pgx.Tx, owner, action, kind, id string, info RequestInfo, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["module"] = "independent_signing"
	return store.New(s.pool).AuditInTx(ctx, tx, store.AuditEvent{ActorUserID: &owner, Action: action, ResourceType: kind, ResourceID: &id, Outcome: "success", RequestID: info.RequestID, SourceIP: &info.IP, UserAgent: info.UserAgent, Metadata: metadata})
}

// All mutations take locks in owner -> instance -> credential -> audit order.
func (s *Service) lockedInstance(ctx context.Context, tx pgx.Tx, id, owner string) (Instance, error) {
	if !validID(id) {
		return Instance{}, missing()
	}
	var actual string
	if err := tx.QueryRow(ctx, `SELECT owner_id::text FROM signing_instances WHERE id=$1`, id).Scan(&actual); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Instance{}, missing()
		}
		return Instance{}, err
	}
	if owner != "" && actual != owner {
		return Instance{}, missing()
	}
	var active string
	err := tx.QueryRow(ctx, `SELECT id::text FROM users WHERE id=$1 AND status='active' FOR SHARE`, actual).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return Instance{}, denied()
	}
	if err != nil {
		return Instance{}, err
	}
	return s.scanInstance(tx.QueryRow(ctx, `SELECT `+instanceColumns+` FROM signing_instances WHERE id=$1 FOR UPDATE`, id))
}

// CheckCredential rejects unauthenticated callers before their request bodies
// can occupy shared cryptographic slots. Mutations still reauthorize under locks.
func (s *Service) CheckCredential(ctx context.Context, instance, token, scope string) error {
	if !validID(instance) || len(token) != 47 || !strings.HasPrefix(token, "ist_") {
		return denied()
	}
	digest := sha256.Sum256([]byte(token))
	var stored []byte
	err := s.pool.QueryRow(ctx, `SELECT c.token_hash FROM signing_credentials c
 JOIN signing_instances i ON i.id=c.instance_id JOIN users u ON u.id=i.owner_id
 WHERE c.instance_id=$1 AND c.token_hash=$2 AND c.revoked_at IS NULL
 AND c.expires_at>$3 AND u.status='active' AND $4=ANY(c.scopes)`, instance, digest[:], s.now(), scope).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return denied()
	}
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest[:], stored) != 1 {
		return denied()
	}
	return nil
}

func (s *Service) authorize(ctx context.Context, tx pgx.Tx, instance Instance, token, scope string) (Credential, error) {
	if len(token) != 47 || !strings.HasPrefix(token, "ist_") {
		return Credential{}, denied()
	}
	digest := sha256.Sum256([]byte(token))
	c, err := scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM signing_credentials WHERE instance_id=$1 AND token_hash=$2 FOR UPDATE`, instance.ID, digest[:]))
	var problem *Error
	if errors.As(err, &problem) && problem.Status == 404 {
		return c, denied()
	}
	if err != nil {
		return c, err
	}
	if subtle.ConstantTimeCompare(digest[:], c.tokenHash) != 1 || c.RevokedAt != nil || !s.now().Before(c.ExpiresAt) {
		return c, denied()
	}
	for _, allowed := range c.Scopes {
		if allowed == scope {
			return c, nil
		}
	}
	return c, denied()
}
func (s *Service) authority(i Instance) (authority, error) {
	plain, err := s.keys.Decrypt(security.Envelope{KeyID: i.kekID, Nonce: i.nonce, Ciphertext: i.ciphertext}, []byte("independent-signing:"+i.ID+":ca-key:v1"))
	if err != nil {
		return authority{}, err
	}
	defer clear(plain)
	return loadAuthority(i.CertificatePEM, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain})), i.ChainPEM, s.now())
}

func (s *Service) List(ctx context.Context, owner string) ([]Instance, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+instanceColumns+` FROM signing_instances WHERE owner_id=$1 ORDER BY id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Instance{}
	for rows.Next() {
		i, err := s.scanInstance(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	return items, rows.Err()
}
func (s *Service) Get(ctx context.Context, owner, id string) (Instance, error) {
	if !validID(id) {
		return Instance{}, missing()
	}
	return s.scanInstance(s.pool.QueryRow(ctx, `SELECT `+instanceColumns+` FROM signing_instances WHERE id=$1 AND owner_id=$2`, id, owner))
}
func (s *Service) Create(ctx context.Context, owner string, input CreateInput, info RequestInfo) (Instance, error) {
	var result Instance
	if len(input.CertificatePEM) > 64<<10 || len(input.PrivateKeyPEM) > 32<<10 || len(input.ChainPEM) > 256<<10 {
		return result, invalid("CA PEM exceeds certificate 64 KiB, private key 32 KiB or chain 256 KiB limit")
	}
	if err := validateName(input.Name); err != nil {
		return result, err
	}
	if err := input.Policy.Validate(); err != nil {
		return result, err
	}
	a, err := loadAuthority(input.CertificatePEM, input.PrivateKeyPEM, input.ChainPEM, s.now())
	if err != nil {
		return result, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return result, err
	}
	defer clear(key)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	var active string
	err = tx.QueryRow(ctx, `SELECT id::text FROM users WHERE id=$1 AND status='active' FOR UPDATE`, owner).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, denied()
	}
	if err != nil {
		return result, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM signing_instances WHERE owner_id=$1`, owner).Scan(&count); err != nil {
		return result, err
	}
	if count >= 50 {
		return result, invalid("Maximum 50 instances per owner")
	}
	var id string
	if err = tx.QueryRow(ctx, `SELECT uuidv7()::text`).Scan(&id); err != nil {
		return result, err
	}
	envelope, err := s.keys.Encrypt(key, []byte("independent-signing:"+id+":ca-key:v1"))
	if err != nil {
		return result, err
	}
	policy, _ := json.Marshal(input.Policy)
	result, err = s.scanInstance(tx.QueryRow(ctx, `INSERT INTO signing_instances(id,owner_id,name,certificate_pem,chain_pem,encrypted_key,key_nonce,kek_id,policy) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+instanceColumns, id, owner, strings.TrimSpace(input.Name), a.pem, a.chainPEM, envelope.Ciphertext, envelope.Nonce, envelope.KeyID, policy))
	if err != nil {
		return result, err
	}
	if err = s.audit(ctx, tx, owner, "signing.instance.create", "signing_instance", id, info, nil); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
func (s *Service) Update(ctx context.Context, owner, id string, input UpdateInput, info RequestInfo) (Instance, error) {
	var result Instance
	if err := validateName(input.Name); err != nil {
		return result, err
	}
	if err := input.Policy.Validate(); err != nil {
		return result, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if _, err = s.lockedInstance(ctx, tx, id, owner); err != nil {
		return result, err
	}
	policy, _ := json.Marshal(input.Policy)
	result, err = s.scanInstance(tx.QueryRow(ctx, `UPDATE signing_instances SET name=$2,policy=$3,enabled=$4,updated_at=now() WHERE id=$1 RETURNING `+instanceColumns, id, strings.TrimSpace(input.Name), policy, input.Enabled))
	if err != nil {
		return result, err
	}
	if err = s.audit(ctx, tx, owner, "signing.instance.update", "signing_instance", id, info, map[string]any{"policy": input.Policy, "enabled": input.Enabled}); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
func (s *Service) Credentials(ctx context.Context, owner, id string) ([]Credential, error) {
	if _, err := s.Get(ctx, owner, id); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+credentialColumns+` FROM signing_credentials WHERE instance_id=$1 ORDER BY id DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Credential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}
func (s *Service) CreateCredential(ctx context.Context, owner, id string, input CredentialInput, info RequestInfo) (Credential, string, error) {
	var c Credential
	if err := validateName(input.Name); err != nil {
		return c, "", err
	}
	if len(input.Scopes) == 0 || len(input.Scopes) > 3 {
		return c, "", invalid("Choose issue, read and/or revoke scopes")
	}
	seen := map[string]bool{}
	for _, scope := range input.Scopes {
		if (scope != "issue" && scope != "read" && scope != "revoke") || seen[scope] {
			return c, "", invalid("Invalid or repeated scope")
		}
		seen[scope] = true
	}
	if input.Policy != nil {
		if err := input.Policy.Validate(); err != nil {
			return c, "", err
		}
	}
	if input.LifetimeSeconds == 0 {
		input.LifetimeSeconds = 30 * 24 * 3600
	}
	if input.MaxIssuances == 0 {
		input.MaxIssuances = 1000
	}
	if input.RatePerMinute == 0 {
		input.RatePerMinute = 10
	}
	if input.LifetimeSeconds < 3600 || input.LifetimeSeconds > 90*24*3600 || input.MaxIssuances < 1 || input.MaxIssuances > 1000000 || input.RatePerMinute < 1 || input.RatePerMinute > 120 {
		return c, "", invalid("Credential lifetime/quota/rate is outside allowed limits")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return c, "", err
	}
	defer tx.Rollback(ctx)
	if _, err = s.lockedInstance(ctx, tx, id, owner); err != nil {
		return c, "", err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM signing_credentials WHERE instance_id=$1`, id).Scan(&count); err != nil {
		return c, "", err
	}
	if count >= 1000 {
		return c, "", invalid("Maximum 1000 credentials per instance")
	}
	raw, _, err := security.NewToken()
	if err != nil {
		return c, "", err
	}
	token := "ist_" + raw
	digest := sha256.Sum256([]byte(token))
	var policy []byte
	if input.Policy != nil {
		policy, _ = json.Marshal(input.Policy)
	}
	c, err = scanCredential(tx.QueryRow(ctx, `INSERT INTO signing_credentials(instance_id,name,token_hash,scopes,policy,max_issuances,rate_per_minute,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+credentialColumns, id, strings.TrimSpace(input.Name), digest[:], input.Scopes, policy, input.MaxIssuances, input.RatePerMinute, s.now().Add(time.Duration(input.LifetimeSeconds)*time.Second)))
	if err != nil {
		return c, "", err
	}
	if err = s.audit(ctx, tx, owner, "signing.credential.create", "signing_credential", c.ID, info, map[string]any{"instance_id": id, "scopes": c.Scopes, "expires_at": c.ExpiresAt}); err != nil {
		return c, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return c, "", err
	}
	return c, token, nil
}
func (s *Service) RevokeCredential(ctx context.Context, owner, id, credential string, info RequestInfo) error {
	if !validID(credential) {
		return missing()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = s.lockedInstance(ctx, tx, id, owner); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE signing_credentials SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1 AND instance_id=$2`, credential, id)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return missing()
	}
	if err = s.audit(ctx, tx, owner, "signing.credential.revoke", "signing_credential", credential, info, map[string]any{"instance_id": id}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func hashRequest(raw []byte) [32]byte { return sha256.Sum256(raw) }
func checkIdempotency(value string) error {
	if len(value) < 8 || len(value) > 128 {
		return &Error{400, "signing_idempotency_required", "Supply an 8..128 byte printable ASCII Idempotency-Key"}
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return &Error{400, "signing_idempotency_required", "Idempotency-Key must be printable ASCII without spaces"}
		}
	}
	return nil
}
