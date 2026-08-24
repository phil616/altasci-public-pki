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
var ErrIdempotencyConflict = errors.New("idempotency key conflicts with another request")

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func scanUser(row pgx.Row) (User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.PasswordHash,
		&user.Status, &user.FailedLoginCount, &user.LockedUntil, &user.TOTPLastStep,
		&user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return user, err
}

const userColumns = `id::text, username, email, role, password_hash, status,
failed_login_count, locked_until, root_totp_last_step, created_at, updated_at`

func (s *Store) UserByLogin(ctx context.Context, login string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users
        WHERE lower(username)=lower($1) OR lower(email)=lower($1) LIMIT 1`, login))
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
          status='active',updated_at=now(),version=users.version+1
        RETURNING `+userColumns, email, passwordHash))
}

func (s *Store) CreateUser(ctx context.Context, username string, email *string, role, passwordHash string) (User, error) {
	if role != "operator" && role != "user" {
		return User{}, errors.New("only operator and user accounts may be created")
	}
	return scanUser(s.pool.QueryRow(ctx, `INSERT INTO users (username,email,role,password_hash)
        VALUES ($1,$2,$3,$4) RETURNING `+userColumns, username, email, role, passwordHash))
}

func (s *Store) RecordLoginFailure(ctx context.Context, userID string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET
        failed_login_count=failed_login_count+1,
        locked_until=CASE WHEN failed_login_count+1 >= 5 THEN $2 + interval '15 minutes' ELSE locked_until END,
        status=CASE WHEN failed_login_count+1 >= 5 THEN 'locked' ELSE status END,
        updated_at=$2 WHERE id=$1`, userID, now)
	return err
}

// AcceptLogin atomically prevents TOTP replay for root and clears transient
// account locks after a successful credential check.
func (s *Store) AcceptLogin(ctx context.Context, user User, totpStep int64, now time.Time) error {
	command, err := s.pool.Exec(ctx, `UPDATE users SET
        root_totp_last_step=CASE WHEN role='super_admin' THEN $2 ELSE root_totp_last_step END,
        failed_login_count=0,locked_until=NULL,status='active',last_login_at=$3,updated_at=$3
        WHERE id=$1 AND status<>'disabled'
          AND (role<>'super_admin' OR root_totp_last_step < $2)`, user.ID, totpStep, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return errors.New("login was rejected or TOTP code was replayed")
	}
	return nil
}

func (s *Store) AcceptRootStepUp(ctx context.Context, userID string, totpStep int64) error {
	command, err := s.pool.Exec(ctx, `UPDATE users SET root_totp_last_step=$2,updated_at=now()
        WHERE id=$1 AND role='super_admin' AND status='active' AND root_totp_last_step<$2`, userID, totpStep)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return errors.New("TOTP step-up code was rejected or replayed")
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
          AND s.absolute_expires_at>$2 AND u.status='active'`, tokenHash, now)
	err := row.Scan(&session.ID, &session.CSRFHash, &session.CreatedAt, &session.LastSeenAt,
		&session.IdleExpiresAt, &session.AbsoluteExpiresAt,
		&session.User.ID, &session.User.Username, &session.User.Email, &session.User.Role,
		&session.User.PasswordHash, &session.User.Status, &session.User.FailedLoginCount,
		&session.User.LockedUntil, &session.User.TOTPLastStep, &session.User.CreatedAt,
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
	command, err := s.pool.Exec(ctx, `UPDATE users SET status=$2,failed_login_count=0,
        locked_until=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND role<>'super_admin'`, userID, status)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrNotFound
	}
	if status == "disabled" {
		_, _ = s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1`, userID)
	}
	return nil
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
	zero := make([]byte, sha256.Size)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_chain_heads(scope,head_hash) VALUES ('global',$1)
        ON CONFLICT (scope) DO NOTHING`, zero); err != nil {
		return err
	}
	var previous []byte
	if err = tx.QueryRow(ctx, `SELECT head_hash FROM audit_chain_heads WHERE scope='global' FOR UPDATE`).Scan(&previous); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pki_create_audit_partition(date_trunc('month',current_date)::date)`); err != nil {
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
	metadata, _ := json.Marshal(event.Metadata)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events
        (actor_user_id,actor_role,session_id,action,resource_type,resource_id,outcome,
         request_id,source_ip,user_agent,cf_access_sub,before_state,after_state,metadata,prev_hash,event_hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::inet,$10,$11,$12,$13,$14,$15,$16)`,
		event.ActorUserID, event.ActorRole, event.SessionID, event.Action, event.ResourceType,
		event.ResourceID, event.Outcome, event.RequestID, stringValue(event.SourceIP), event.UserAgent,
		event.AccessSub, nullableJSON(before), nullableJSON(after), nullableJSON(metadata), previous, digest)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE audit_chain_heads SET head_hash=$1,updated_at=now() WHERE scope='global'`, digest); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func userColumnsWithAlias(alias string) string {
	return alias + `.id::text,` + alias + `.username,` + alias + `.email,` + alias + `.role,` +
		alias + `.password_hash,` + alias + `.status,` + alias + `.failed_login_count,` +
		alias + `.locked_until,` + alias + `.root_totp_last_step,` + alias + `.created_at,` + alias + `.updated_at`
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
