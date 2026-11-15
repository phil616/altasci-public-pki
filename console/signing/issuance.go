package signing

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Service) Issue(ctx context.Context, id, token, key string, input IssueInput, raw []byte, info RequestInfo) (Certificate, bool, error) {
	var result Certificate
	if err := checkIdempotency(key); err != nil {
		return result, false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, false, err
	}
	defer tx.Rollback(ctx)
	i, err := s.lockedInstance(ctx, tx, id, "")
	if err != nil {
		return result, false, err
	}
	c, err := s.authorize(ctx, tx, i, token, "issue")
	if err != nil {
		return result, false, err
	}
	digest := hashRequest(raw)
	var previous []byte
	var previousID string
	err = tx.QueryRow(ctx, `SELECT id::text,request_hash FROM signing_certificates WHERE credential_id=$1 AND idempotency_key=$2`, c.ID, key).Scan(&previousID, &previous)
	if err == nil {
		if subtle.ConstantTimeCompare(previous, digest[:]) != 1 {
			return result, false, &Error{409, "signing_idempotency_conflict", "Key is already bound to different request content"}
		}
		result, err = s.scanCertificate(tx.QueryRow(ctx, `SELECT `+certificateColumns+` FROM signing_certificates WHERE id=$1`, previousID))
		return result, true, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, false, err
	}
	if !i.Enabled {
		return result, false, &Error{403, "signing_disabled", "Instance is disabled for new issuance"}
	}
	if c.IssuedCount >= c.MaxIssuances {
		return result, false, &Error{403, "signing_quota_exhausted", "Credential issuance quota is exhausted"}
	}
	now := s.now().UTC()
	if now.Sub(c.rateWindow) >= time.Minute {
		c.rateWindow = now
		c.rateCount = 0
	}
	if c.rateCount >= c.RatePerMinute {
		return result, false, &Error{429, "signing_rate_limited", "Credential issuance rate exceeded; retry after one minute"}
	}
	if err = i.Policy.Validate(); err != nil {
		return result, false, err
	}
	csr, err := parseCSR(input.CSRPEM)
	if err != nil {
		return result, false, err
	}
	if err = validateRequest(csr, i.Policy); err != nil {
		return result, false, err
	}
	seconds := input.ValiditySeconds
	defaultSeconds := i.Policy.DefaultValiditySeconds
	maxSeconds := i.Policy.MaxValiditySeconds
	ekus := append([]string{}, i.Policy.ExtendedKeyUsages...)
	if c.Policy != nil {
		if err = c.Policy.Validate(); err != nil {
			return result, false, err
		}
		if err = validateRequest(csr, *c.Policy); err != nil {
			return result, false, err
		}
		defaultSeconds = min(defaultSeconds, c.Policy.DefaultValiditySeconds)
		maxSeconds = min(maxSeconds, c.Policy.MaxValiditySeconds)
		ekus = slices.DeleteFunc(ekus, func(usage string) bool { return !slices.Contains(c.Policy.ExtendedKeyUsages, usage) })
	}
	if len(ekus) == 0 {
		return result, false, invalid("Instance and credential have no shared certificate usage")
	}
	if seconds == 0 {
		seconds = defaultSeconds
	}
	if seconds < 60 || seconds > maxSeconds {
		return result, false, invalid("Requested validity is outside policy limits")
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM signing_certificates WHERE instance_id=$1`, id).Scan(&count); err != nil {
		return result, false, err
	}
	if count >= 50000 {
		return result, false, invalid("Instance lifetime limit of 50000 certificates reached")
	}
	a, err := s.authority(i)
	if err != nil {
		return result, false, err
	}
	result, err = a.issue(csr, i.ID, s.base, seconds, ekus, now)
	if err != nil {
		return result, false, err
	}
	result, err = s.scanCertificate(tx.QueryRow(ctx, `INSERT INTO signing_certificates(instance_id,credential_id,serial,certificate_pem,chain_pem,fingerprint_sha256,not_before,not_after,idempotency_key,request_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+certificateColumns, id, c.ID, result.Serial, result.CertificatePEM, result.ChainPEM, result.FingerprintSHA256, result.NotBefore, result.NotAfter, key, digest[:]))
	if err != nil {
		return result, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE signing_credentials SET issued_count=issued_count+1,rate_window=$2,rate_count=$3 WHERE id=$1`, c.ID, c.rateWindow, c.rateCount+1); err != nil {
		return result, false, err
	}
	if err = s.audit(ctx, tx, i.OwnerID, "signing.certificate.issue", "signing_certificate", result.ID, info, map[string]any{"instance_id": id, "credential_id": c.ID}); err != nil {
		return result, false, err
	}
	return result, false, tx.Commit(ctx)
}

func (s *Service) Certificates(ctx context.Context, owner, id, before string, limit int) ([]Certificate, string, error) {
	if _, err := s.Get(ctx, owner, id); err != nil {
		return nil, "", err
	}
	if before != "" && !validID(before) {
		return nil, "", &Error{400, "signing_invalid_cursor", "Invalid certificate cursor"}
	}
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+certificateColumns+` FROM signing_certificates WHERE instance_id=$1 AND ($2='' OR id<NULLIF($2,'')::uuid) ORDER BY id DESC LIMIT $3`, id, before, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := []Certificate{}
	for rows.Next() {
		c, err := s.scanCertificate(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, c)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = items[len(items)-1].ID
	}
	return items, next, nil
}

func (s *Service) PublicCertificate(ctx context.Context, id, certificate, token string) (Certificate, error) {
	var result Certificate
	if !validID(certificate) {
		return result, missing()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	i, err := s.lockedInstance(ctx, tx, id, "")
	if err != nil {
		return result, err
	}
	c, err := s.authorize(ctx, tx, i, token, "read")
	if err != nil {
		return result, err
	}
	return s.scanCertificate(tx.QueryRow(ctx, `SELECT `+certificateColumns+` FROM signing_certificates WHERE id=$1 AND instance_id=$2 AND credential_id=$3`, certificate, id, c.ID))
}

// Owner credentials and bearer credentials use separate authorization paths;
// a token can never revoke certificates issued by a different credential.
func (s *Service) Revoke(ctx context.Context, owner, id, certificate, token string, reason int, info RequestInfo) (Certificate, error) {
	var result Certificate
	if !validID(certificate) {
		return result, missing()
	}
	if reason < 0 || reason > 10 || (reason == 7 || reason == 8) {
		return result, invalid("Invalid revocation reason")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	i, err := s.lockedInstance(ctx, tx, id, owner)
	if err != nil {
		return result, err
	}
	credential := ""
	if owner == "" {
		c, err := s.authorize(ctx, tx, i, token, "revoke")
		if err != nil {
			return result, err
		}
		credential = c.ID
	}
	result, err = s.scanCertificate(tx.QueryRow(ctx, `SELECT `+certificateColumns+` FROM signing_certificates WHERE id=$1 AND instance_id=$2 AND ($3='' OR credential_id=NULLIF($3,'')::uuid) FOR UPDATE`, certificate, id, credential))
	if err != nil {
		return result, err
	}
	if result.RevokedAt != nil {
		if result.RevocationReason != nil && *result.RevocationReason == reason {
			return result, nil
		}
		return result, &Error{409, "signing_already_revoked", "Certificate was revoked with a different reason"}
	}
	result, err = s.scanCertificate(tx.QueryRow(ctx, `UPDATE signing_certificates SET revoked_at=now(),revocation_reason=$2 WHERE id=$1 RETURNING `+certificateColumns, certificate, reason))
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE signing_instances SET crl_der=NULL,crl_next_update=NULL WHERE id=$1`, id); err != nil {
		return result, err
	}
	if err = s.audit(ctx, tx, i.OwnerID, "signing.certificate.revoke", "signing_certificate", certificate, info, map[string]any{"instance_id": id, "credential_id": credential, "reason": reason}); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (s *Service) Issuer(ctx context.Context, id string) ([]byte, error) {
	if !validID(id) {
		return nil, missing()
	}
	var pem string
	err := s.pool.QueryRow(ctx, `SELECT certificate_pem FROM signing_instances WHERE id=$1`, id).Scan(&pem)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, missing()
	}
	if err != nil {
		return nil, err
	}
	certs, err := parseCertificates(pem)
	if err != nil || len(certs) != 1 {
		return nil, errors.New("invalid stored issuer")
	}
	return certs[0].Raw, nil
}

func (s *Service) CRL(ctx context.Context, id string, info RequestInfo) ([]byte, error) {
	if !validID(id) {
		return nil, missing()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var owner string
	if err = tx.QueryRow(ctx, `SELECT owner_id::text FROM signing_instances WHERE id=$1`, id).Scan(&owner); errors.Is(err, pgx.ErrNoRows) {
		return nil, missing()
	} else if err != nil {
		return nil, err
	}
	// Publication remains available after owner disablement and instance suspension.
	var locked string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM users WHERE id=$1 FOR SHARE`, owner).Scan(&locked); err != nil {
		return nil, err
	}
	i, err := s.scanInstance(tx.QueryRow(ctx, `SELECT `+instanceColumns+` FROM signing_instances WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return nil, err
	}
	var cached []byte
	var next *time.Time
	var number int64
	if err = tx.QueryRow(ctx, `SELECT crl_der,crl_next_update,crl_number FROM signing_instances WHERE id=$1`, id).Scan(&cached, &next, &number); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if len(cached) > 0 && next != nil && next.After(now.Add(time.Minute)) {
		return cached, nil
	}
	a, err := s.authority(i)
	if err != nil {
		return nil, err
	}
	expires := now.Add(24 * time.Hour)
	if expiry := a.earliestExpiry(); expiry.Before(expires) {
		expires = expiry
	}
	if !expires.After(now) {
		return nil, invalid("CA chain has expired; current CRL cannot be signed")
	}
	rows, err := tx.Query(ctx, `SELECT serial::text,revoked_at,revocation_reason FROM signing_certificates WHERE instance_id=$1 AND revoked_at IS NOT NULL ORDER BY serial`, id)
	if err != nil {
		return nil, err
	}
	entries := []x509.RevocationListEntry{}
	for rows.Next() {
		var serial string
		var revoked time.Time
		var reason int
		if err = rows.Scan(&serial, &revoked, &reason); err != nil {
			rows.Close()
			return nil, err
		}
		value, ok := new(big.Int).SetString(serial, 10)
		if !ok {
			rows.Close()
			return nil, errors.New("invalid stored serial")
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: value, RevocationTime: revoked, ReasonCode: reason})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	template := &x509.RevocationList{Number: big.NewInt(number + 1), ThisUpdate: now, NextUpdate: expires, RevokedCertificateEntries: entries, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: issuingDistributionPoint(s.base + "/signing/" + i.ID + "/crl")}}}
	der, err := x509.CreateRevocationList(rand.Reader, template, a.cert, a.key)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE signing_instances SET crl_number=$2,crl_der=$3,crl_next_update=$4 WHERE id=$1`, id, number+1, der, expires); err != nil {
		return nil, err
	}
	if err = s.audit(ctx, tx, owner, "signing.crl.publish", "signing_instance", id, info, map[string]any{"number": number + 1}); err != nil {
		return nil, err
	}
	return der, tx.Commit(ctx)
}
