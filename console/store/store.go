package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("record not found")
var ErrCredentialStateChanged = errors.New("verified credentials are no longer current")
var ErrIdempotencyConflict = errors.New("idempotency key conflicts with another request")
var ErrTimestampSerialCollision = errors.New("timestamp serial already exists")

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func scanUser(row pgx.Row) (User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.PasswordHash,
		&user.Status, &user.FailedLoginCount, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return user, err
}

const userColumns = `id::text, username, email, role, password_hash, status,
failed_login_count, locked_until, created_at, updated_at`

func (s *Store) UserByLogin(ctx context.Context, login string) (User, error) {
	// Legacy data may reuse one account's email as another account's username.
	// Never choose an arbitrary identity when a login matches multiple accounts.
	return scanUser(s.pool.QueryRow(ctx, `WITH matches AS (SELECT `+userColumns+` FROM users
        WHERE lower(username)=lower($1) OR lower(email)=lower($1) LIMIT 2)
        SELECT * FROM matches WHERE (SELECT count(*) FROM matches)=1`, login))
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id=$1`, id))
}

func (s *Store) RootUser(ctx context.Context) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE role='super_admin'`))
}

func (s *Store) UpsertRoot(ctx context.Context, email, passwordHash string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `INSERT INTO users (username,email,role,password_hash)
        VALUES ($1,$1,'super_admin',$2)
        ON CONFLICT (role) WHERE role='super_admin' DO UPDATE SET
          username=EXCLUDED.username,email=EXCLUDED.email,password_hash=EXCLUDED.password_hash,
          password_changed_at=CASE WHEN users.password_hash<>EXCLUDED.password_hash THEN now() ELSE users.password_changed_at END,
          failed_login_count=0,locked_until=NULL,status='active',updated_at=now(),version=users.version+1
        RETURNING `+userColumns, email, passwordHash))
}

func (s *Store) CreateUser(ctx context.Context, username string, email *string, role, passwordHash string) (User, error) {
	if role != "operator" && role != "user" {
		return User{}, errors.New("only operator and user accounts may be created")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	// Serialize account creation so the cross-column check cannot race another
	// creation. Root upserts set BOTH identifiers to the email and are additionally
	// protected by the two existing unique indexes.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('pki-console:user-login-identifiers',0))`); err != nil {
		return User{}, err
	}
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users
        WHERE lower(username)=lower($1) OR lower(email)=lower($1)
           OR ($2::text IS NOT NULL AND (lower(username)=lower($2) OR lower(email)=lower($2))))`, username, email).Scan(&conflict); err != nil {
		return User{}, err
	}
	if conflict {
		return User{}, errors.New("username or email conflicts with an existing login identifier")
	}
	user, err := scanUser(tx.QueryRow(ctx, `INSERT INTO users (username,email,role,password_hash)
        VALUES ($1,$2,$3,$4) RETURNING `+userColumns, username, email, role, passwordHash))
	if err != nil {
		return User{}, err
	}
	return user, tx.Commit(ctx)
}

func (s *Store) RecordLoginFailure(ctx context.Context, userID string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET
        failed_login_count=CASE WHEN locked_until<=$2 THEN 1 ELSE failed_login_count+1 END,
        locked_until=CASE WHEN locked_until<=$2 THEN NULL
          WHEN failed_login_count+1 >= 5 THEN $2::timestamptz + interval '15 minutes' ELSE locked_until END,
        status=CASE WHEN locked_until<=$2 THEN 'active'
          WHEN failed_login_count+1 >= 5 THEN 'locked' ELSE status END,
        updated_at=$2 WHERE id=$1 AND status<>'disabled'
          AND (locked_until IS NULL OR locked_until<=$2)`, userID, now)
	return err
}

// CreateAuthenticatedSession rechecks the verified credential snapshot while
// holding the account row lock. Password resets and disables
// cannot race between credential verification and session creation.
func (s *Store) CreateAuthenticatedSession(ctx context.Context, user User, tokenHash, csrfHash []byte, idle, absolute, now time.Time, ip, userAgent string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `UPDATE users SET
        failed_login_count=0,locked_until=NULL,status='active',last_login_at=$3,updated_at=$3
        WHERE id=$1 AND password_hash=$2 AND role=$4 AND status<>'disabled'
          AND (locked_until IS NULL OR locked_until<=$3)
        RETURNING id::text`, user.ID, user.PasswordHash, now, user.Role).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrCredentialStateChanged
		}
		return "", err
	}
	err = tx.QueryRow(ctx, `INSERT INTO sessions
        (user_id,token_hash,csrf_hash,idle_expires_at,absolute_expires_at,ip,user_agent)
        VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::inet,$7) RETURNING id::text`,
		user.ID, tokenHash, csrfHash, idle, absolute, ip, userAgent).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

func (s *Store) VerifyRootPasswordSnapshot(ctx context.Context, userID, passwordHash string) error {
	var current bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users
        WHERE id=$1 AND role='super_admin' AND status='active' AND password_hash=$2)`, userID, passwordHash).Scan(&current)
	if err != nil {
		return err
	}
	if !current {
		return ErrCredentialStateChanged
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, userID string, tokenHash, csrfHash []byte, idle, absolute time.Time, ip, userAgent string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO sessions
        (user_id,token_hash,csrf_hash,idle_expires_at,absolute_expires_at,ip,user_agent)
        VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::inet,$7) RETURNING id::text`,
		userID, tokenHash, csrfHash, idle, absolute, ip, userAgent).Scan(&id)
	return id, err
}

func (s *Store) SessionByToken(ctx context.Context, tokenHash []byte, now time.Time) (Session, error) {
	var session Session
	row := s.pool.QueryRow(ctx, `SELECT s.id::text,s.csrf_hash,s.created_at,s.last_seen_at,
        s.idle_expires_at,s.absolute_expires_at,`+userColumnsWithAlias("u")+`
        FROM sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.idle_expires_at>$2
          AND s.absolute_expires_at>$2 AND u.status='active'
          AND s.created_at>=u.password_changed_at`, tokenHash, now)
	err := row.Scan(&session.ID, &session.CSRFHash, &session.CreatedAt, &session.LastSeenAt,
		&session.IdleExpiresAt, &session.AbsoluteExpiresAt,
		&session.User.ID, &session.User.Username, &session.User.Email, &session.User.Role,
		&session.User.PasswordHash, &session.User.Status, &session.User.FailedLoginCount,
		&session.User.LockedUntil, &session.User.CreatedAt,
		&session.User.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return session, err
}

func (s *Store) TouchSession(ctx context.Context, sessionID string, idleExpires, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=$2,
        idle_expires_at=LEAST($3,absolute_expires_at) WHERE id=$1`, sessionID, now, idleExpires)
	return err
}

func (s *Store) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1`, sessionID)
	return err
}

type IdempotencyResult struct {
	ResponseCode int
	ResponseBody json.RawMessage
	Ready        bool
}

func (s *Store) ClaimIdempotency(ctx context.Context, userID, scope, key string, requestHash []byte) (IdempotencyResult, bool, error) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE expires_at<=now()`)
	command, err := s.pool.Exec(ctx, `INSERT INTO idempotency_keys(user_id,scope,key,request_hash,expires_at)
        VALUES ($1,$2,$3,$4,now()+interval '24 hours') ON CONFLICT DO NOTHING`, userID, scope, key, requestHash)
	if err != nil {
		return IdempotencyResult{}, false, err
	}
	if command.RowsAffected() == 1 {
		return IdempotencyResult{}, true, nil
	}
	var storedHash []byte
	var code *int
	var body json.RawMessage
	err = s.pool.QueryRow(ctx, `SELECT request_hash,response_code,response_body FROM idempotency_keys
        WHERE user_id=$1 AND scope=$2 AND key=$3`, userID, scope, key).Scan(&storedHash, &code, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdempotencyResult{}, false, ErrIdempotencyConflict
	}
	if err != nil {
		return IdempotencyResult{}, false, err
	}
	if !bytes.Equal(storedHash, requestHash) || code == nil {
		return IdempotencyResult{}, false, ErrIdempotencyConflict
	}
	var exactBody string
	if len(body) > 0 && string(body) != "null" {
		if err := json.Unmarshal(body, &exactBody); err != nil {
			return IdempotencyResult{}, false, err
		}
	}
	return IdempotencyResult{ResponseCode: *code, ResponseBody: json.RawMessage(exactBody), Ready: true}, false, nil
}

func (s *Store) CompleteIdempotency(ctx context.Context, userID, scope, key string, requestHash []byte, code int, body []byte) error {
	var response any
	if len(body) > 0 {
		if !json.Valid(body) {
			return errors.New("idempotent response must be JSON")
		}
		encoded, err := json.Marshal(string(body))
		if err != nil {
			return err
		}
		response = string(encoded)
	}
	_, err := s.pool.Exec(ctx, `UPDATE idempotency_keys SET response_code=$5,response_body=$6
        WHERE user_id=$1 AND scope=$2 AND key=$3 AND request_hash=$4`, userID, scope, key, requestHash, code, response)
	return err
}

func (s *Store) AbortIdempotency(ctx context.Context, userID, scope, key string, requestHash []byte) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE user_id=$1 AND scope=$2 AND key=$3
        AND request_hash=$4 AND response_code IS NULL`, userID, scope, key, requestHash)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at,id LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) SetUserStatus(ctx context.Context, userID, status string) error {
	if status != "active" && status != "disabled" {
		return errors.New("status must be active or disabled")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `UPDATE users SET status=$2,failed_login_count=0,
        locked_until=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND role<>'super_admin'`, userID, status)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrNotFound
	}
	if status == "disabled" {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1`, userID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ResetUserPassword(ctx context.Context, userID, passwordHash string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2,password_changed_at=now(),
        failed_login_count=0,locked_until=NULL,updated_at=now(),version=version+1
        WHERE id=$1 AND role<>'super_admin'`, userID, passwordHash)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GrantCA(ctx context.Context, caID, userID, permission, grantedBy string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO ca_grants(ca_id,user_id,permission,granted_by)
        VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, caID, userID, permission, grantedBy)
	return err
}

func (s *Store) HasCAGrant(ctx context.Context, caID, userID, permission string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ca_grants
        WHERE ca_id=$1 AND user_id=$2 AND permission=$3)`, caID, userID, permission).Scan(&allowed)
	return allowed, err
}

func (s *Store) ListCAGrants(ctx context.Context, caID string) ([]CAGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT ca_id::text,user_id::text,permission,granted_by::text,created_at
        FROM ca_grants WHERE ca_id=$1 ORDER BY user_id,permission`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []CAGrant
	for rows.Next() {
		var grant CAGrant
		if err := rows.Scan(&grant.CAID, &grant.UserID, &grant.Permission, &grant.GrantedBy, &grant.CreatedAt); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (s *Store) RevokeCAGrant(ctx context.Context, caID, userID, permission string) error {
	command, err := s.pool.Exec(ctx, `DELETE FROM ca_grants WHERE ca_id=$1 AND user_id=$2 AND permission=$3`, caID, userID, permission)
	if err == nil && command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) Audit(ctx context.Context, event AuditEvent) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.AuditInTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AuditInTx appends to the same global hash chain in the caller's transaction.
// Call it after locking business records, and commit the transaction only on success.
func (s *Store) AuditInTx(ctx context.Context, tx pgx.Tx, event AuditEvent) error {
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	zero := make([]byte, sha256.Size)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_chain_heads(scope,head_hash) VALUES ('global',$1)
        ON CONFLICT (scope) DO NOTHING`, zero); err != nil {
		return err
	}
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT head_hash FROM audit_chain_heads WHERE scope='global' FOR UPDATE`).Scan(&previous); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pki_create_audit_partition(date_trunc('month',current_date)::date)`); err != nil {
		return err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	_, _ = hasher.Write(previous)
	_, _ = hasher.Write(payload)
	digest := hasher.Sum(nil)
	before, _ := json.Marshal(event.BeforeState)
	after, _ := json.Marshal(event.AfterState)
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events
        (actor_user_id,actor_role,session_id,action,resource_type,resource_id,outcome,
         request_id,source_ip,user_agent,cf_access_sub,before_state,after_state,metadata,prev_hash,event_hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::inet,$10,$11,$12,$13,$14,$15,$16)`,
		event.ActorUserID, event.ActorRole, event.SessionID, event.Action, event.ResourceType,
		event.ResourceID, event.Outcome, event.RequestID, stringValue(event.SourceIP), event.UserAgent,
		event.AccessSub, nullableJSON(before), nullableJSON(after), metadata, previous, digest)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_chain_heads SET head_hash=$1,updated_at=now() WHERE scope='global'`, digest); err != nil {
		return err
	}
	return nil
}

func userColumnsWithAlias(alias string) string {
	return alias + `.id::text,` + alias + `.username,` + alias + `.email,` + alias + `.role,` +
		alias + `.password_hash,` + alias + `.status,` + alias + `.failed_login_count,` +
		alias + `.locked_until,` + alias + `.created_at,` + alias + `.updated_at`
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nullableJSON(value []byte) any {
	if string(value) == "null" || len(value) == 0 {
		return nil
	}
	return string(value)
}

func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]AuditRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id::text,actor_user_id::text,actor_role,session_id::text,
        action,resource_type,resource_id::text,outcome,request_id,source_ip::text,user_agent,
        cf_access_sub,before_state,after_state,metadata,prev_hash,event_hash,occurred_at
        FROM audit_events ORDER BY occurred_at DESC,id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []AuditRecord
	for rows.Next() {
		var item AuditRecord
		var previousHash, eventHash []byte
		if err := rows.Scan(&item.ID, &item.ActorUserID, &item.ActorRole, &item.SessionID,
			&item.Action, &item.ResourceType, &item.ResourceID, &item.Outcome, &item.RequestID,
			&item.SourceIP, &item.UserAgent, &item.AccessSub, &item.BeforeState, &item.AfterState,
			&item.Metadata, &previousHash, &eventHash, &item.OccurredAt); err != nil {
			return nil, err
		}
		item.PreviousHash = hex.EncodeToString(previousHash)
		item.EventHash = hex.EncodeToString(eventHash)
		records = append(records, item)
	}
	return records, rows.Err()
}
