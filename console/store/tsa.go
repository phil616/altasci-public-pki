package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const timestampAuthorityColumns = `id::text,ca_id::text,slug,name,policy_oid,certificate_pem,chain_pem,
encrypted_pkcs8,nonce,kek_id,allowed_hashes,not_before,not_after,status,created_by::text,created_at`

func scanTimestampAuthority(row pgx.Row) (TimestampAuthority, error) {
	var authority TimestampAuthority
	err := row.Scan(&authority.ID, &authority.CAID, &authority.Slug, &authority.Name,
		&authority.PolicyOID, &authority.CertificatePEM, &authority.ChainPEM,
		&authority.EncryptedPKCS8, &authority.Nonce, &authority.KEKID,
		&authority.AllowedHashes, &authority.NotBefore, &authority.NotAfter,
		&authority.Status, &authority.CreatedBy, &authority.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TimestampAuthority{}, ErrNotFound
	}
	return authority, err
}

func (s *Store) InsertTimestampAuthority(ctx context.Context, authority TimestampAuthority) (TimestampAuthority, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO timestamp_authorities
        (id,ca_id,slug,name,policy_oid,certificate_pem,chain_pem,encrypted_pkcs8,nonce,kek_id,
         allowed_hashes,not_before,not_after,status,created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        RETURNING `+timestampAuthorityColumns, authority.ID, authority.CAID, authority.Slug,
		authority.Name, authority.PolicyOID, authority.CertificatePEM, authority.ChainPEM,
		authority.EncryptedPKCS8, authority.Nonce, authority.KEKID, authority.AllowedHashes,
		authority.NotBefore, authority.NotAfter, authority.Status, authority.CreatedBy)
	return scanTimestampAuthority(row)
}

func (s *Store) TimestampAuthorityBySlug(ctx context.Context, slug string) (TimestampAuthority, error) {
	return scanTimestampAuthority(s.pool.QueryRow(ctx, `SELECT `+timestampAuthorityColumns+`
        FROM timestamp_authorities WHERE slug=$1`, slug))
}

func (s *Store) ListTimestampAuthorities(ctx context.Context, caID string) ([]TimestampAuthority, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+timestampAuthorityColumns+`
        FROM timestamp_authorities WHERE ca_id=$1 ORDER BY created_at DESC,id DESC`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	authorities := make([]TimestampAuthority, 0)
	for rows.Next() {
		authority, err := scanTimestampAuthority(rows)
		if err != nil {
			return nil, err
		}
		authorities = append(authorities, authority)
	}
	return authorities, rows.Err()
}

// SaveTimestampToken durably records a token before it can be returned to the
// requester. The named unique constraint turns the RFC 3161 serial uniqueness
// requirement into a database-enforced invariant across processes and restarts.
func (s *Store) SaveTimestampToken(ctx context.Context, token TimestampToken) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO timestamp_tokens
        (tsa_id,serial,hash_algorithm,message_imprint,policy_oid,nonce,generated_at,
         accuracy_micros,token_sha256,token_der)
        VALUES ($1,$2::numeric,$3,$4,$5,$6,$7,$8,$9,$10)`, token.TSAID, token.Serial,
		token.HashAlgorithm, token.MessageImprint, token.PolicyOID, token.Nonce,
		token.GeneratedAt, token.AccuracyMicros, token.TokenSHA256, token.TokenDER)
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "timestamp_tokens_tsa_serial_uq" {
		return ErrTimestampSerialCollision
	}
	return err
}
