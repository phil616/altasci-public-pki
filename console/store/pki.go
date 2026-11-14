package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Store) NewID(ctx context.Context) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `SELECT uuidv7()::text`).Scan(&id)
	return id, err
}

func (s *Store) InsertCA(ctx context.Context, ca CertificateAuthority, key CAKeyVersion, profile SigningProfile, responder OCSPResponder) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO certificate_authorities
        (id,parent_ca_id,slug,name,kind,status,subject,serial,ski,aki,certificate_pem,
         chain_pem,not_before,not_after,path_length,crl_url,ocsp_url,issuer_url,created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		ca.ID, ca.ParentCAID, ca.Slug, ca.Name, ca.Kind, ca.Status, ca.Subject, ca.Serial,
		ca.SKI, nullableBytes(ca.AKI), ca.CertificatePEM, ca.ChainPEM, ca.NotBefore, ca.NotAfter,
		ca.PathLength, ca.CRLURL, ca.OCSPURL, ca.IssuerURL, ca.CreatedBy)
	if err != nil {
		return fmt.Errorf("insert certificate authority: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO ca_key_versions
        (id,ca_id,version,algorithm,public_key_fingerprint,encrypted_pkcs8,nonce,kek_id,status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, key.ID, ca.ID, key.Version, key.Algorithm,
		key.PublicKeyFingerprint, key.EncryptedPKCS8, key.Nonce, key.KEKID, key.Status)
	if err != nil {
		return fmt.Errorf("insert CA key: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO signing_profiles
        (id,ca_id,name,description,default_validity,max_validity,key_usages,extended_key_usages,
         allowed_dns_patterns,allowed_ip_ranges,allow_email_sans,allow_uri_sans,policy,enabled)
        VALUES ($1,$2,$3,$4,make_interval(secs=>$5),make_interval(secs=>$6),$7,$8,$9,$10::cidr[],$11,$12,$13,$14)`,
		profile.ID, ca.ID, profile.Name, profile.Description, int64(profile.DefaultValidity.Seconds()),
		int64(profile.MaxValidity.Seconds()), profile.KeyUsages, profile.ExtendedKeyUsages,
		profile.AllowedDNSPatterns, profile.AllowedIPRanges, profile.AllowEmailSANs, profile.AllowURISANs,
		profile.Policy, profile.Enabled)
	if err != nil {
		return fmt.Errorf("insert default signing profile: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO ocsp_responders
        (id,ca_id,certificate_pem,encrypted_pkcs8,nonce,kek_id,not_before,not_after,status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, responder.ID, ca.ID, responder.CertificatePEM,
		responder.EncryptedPKCS8, responder.Nonce, responder.KEKID, responder.NotBefore,
		responder.NotAfter, responder.Status)
	if err != nil {
		return fmt.Errorf("insert OCSP responder: %w", err)
	}
	return tx.Commit(ctx)
}

const caColumns = `id::text,parent_ca_id::text,slug,name,kind,status,subject,serial::text,ski,aki,
certificate_pem,chain_pem,not_before,not_after,path_length,crl_url,ocsp_url,issuer_url,
created_by::text,created_at`

func scanCA(row pgx.Row) (CertificateAuthority, error) {
	var ca CertificateAuthority
	err := row.Scan(&ca.ID, &ca.ParentCAID, &ca.Slug, &ca.Name, &ca.Kind, &ca.Status,
		&ca.Subject, &ca.Serial, &ca.SKI, &ca.AKI, &ca.CertificatePEM, &ca.ChainPEM,
		&ca.NotBefore, &ca.NotAfter, &ca.PathLength, &ca.CRLURL, &ca.OCSPURL,
		&ca.IssuerURL, &ca.CreatedBy, &ca.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CertificateAuthority{}, ErrNotFound
	}
	return ca, err
}

func (s *Store) CAByID(ctx context.Context, id string) (CertificateAuthority, error) {
	return scanCA(s.pool.QueryRow(ctx, `SELECT `+caColumns+` FROM certificate_authorities WHERE id=$1`, id))
}

func (s *Store) CABySlug(ctx context.Context, slug string) (CertificateAuthority, error) {
	return scanCA(s.pool.QueryRow(ctx, `SELECT `+caColumns+` FROM certificate_authorities WHERE slug=$1`, slug))
}

func (s *Store) ListCAs(ctx context.Context, activeOnly bool) ([]CertificateAuthority, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+caColumns+` FROM certificate_authorities
        WHERE NOT $1 OR status='active' ORDER BY created_at,id LIMIT 500`, activeOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]CertificateAuthority, 0)
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ca)
	}
	return out, rows.Err()
}

func (s *Store) ActiveCAKey(ctx context.Context, caID string) (CAKeyVersion, error) {
	var key CAKeyVersion
	err := s.pool.QueryRow(ctx, `SELECT id::text,ca_id::text,version,algorithm,public_key_fingerprint,
        encrypted_pkcs8,nonce,kek_id,status FROM ca_key_versions WHERE ca_id=$1 AND status='active'`, caID).
		Scan(&key.ID, &key.CAID, &key.Version, &key.Algorithm, &key.PublicKeyFingerprint,
			&key.EncryptedPKCS8, &key.Nonce, &key.KEKID, &key.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return CAKeyVersion{}, ErrNotFound
	}
	return key, err
}

func (s *Store) ActiveOCSPResponder(ctx context.Context, caID string) (OCSPResponder, error) {
	var responder OCSPResponder
	err := s.pool.QueryRow(ctx, `SELECT id::text,ca_id::text,certificate_pem,encrypted_pkcs8,
        nonce,kek_id,not_before,not_after,status FROM ocsp_responders
        WHERE ca_id=$1 AND status='active' AND not_before<=now() AND not_after>now()`, caID).
		Scan(&responder.ID, &responder.CAID, &responder.CertificatePEM, &responder.EncryptedPKCS8,
			&responder.Nonce, &responder.KEKID, &responder.NotBefore, &responder.NotAfter, &responder.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return OCSPResponder{}, ErrNotFound
	}
	return responder, err
}

func scanProfile(row pgx.Row) (SigningProfile, error) {
	var profile SigningProfile
	var defaultSeconds, maxSeconds float64
	err := row.Scan(&profile.ID, &profile.CAID, &profile.Name, &profile.Description,
		&defaultSeconds, &maxSeconds, &profile.KeyUsages, &profile.ExtendedKeyUsages,
		&profile.AllowedDNSPatterns, &profile.AllowedIPRanges, &profile.AllowEmailSANs, &profile.AllowURISANs,
		&profile.Policy, &profile.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return SigningProfile{}, ErrNotFound
	}
	profile.DefaultValidity = time.Duration(defaultSeconds * float64(time.Second))
	profile.MaxValidity = time.Duration(maxSeconds * float64(time.Second))
	return profile, err
}

const profileColumns = `id::text,ca_id::text,name,description,extract(epoch from default_validity),
extract(epoch from max_validity),key_usages,extended_key_usages,allowed_dns_patterns,
allowed_ip_ranges::text[],allow_email_sans,allow_uri_sans,policy,enabled`

func (s *Store) ProfileByID(ctx context.Context, id string) (SigningProfile, error) {
	return scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColumns+` FROM signing_profiles WHERE id=$1`, id))
}

func (s *Store) DefaultProfileForCA(ctx context.Context, caID string) (SigningProfile, error) {
	return scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColumns+` FROM signing_profiles
        WHERE ca_id=$1 AND name='default' AND enabled`, caID))
}

func (s *Store) ListProfiles(ctx context.Context, caID string) ([]SigningProfile, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+profileColumns+` FROM signing_profiles WHERE ca_id=$1 ORDER BY name`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	profiles := make([]SigningProfile, 0)
	for rows.Next() {
		profile, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, rows.Err()
}

func (s *Store) CreateProfile(ctx context.Context, profile SigningProfile) (SigningProfile, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO signing_profiles
        (ca_id,name,description,default_validity,max_validity,key_usages,extended_key_usages,
         allowed_dns_patterns,allowed_ip_ranges,allow_email_sans,allow_uri_sans,policy,enabled)
        SELECT $1,$2,$3,make_interval(secs=>$4),make_interval(secs=>$5),$6,$7,$8,$9::cidr[],$10,$11,$12,$13
        FROM certificate_authorities WHERE id=$1 AND kind='intermediate'
        RETURNING `+profileColumns, profile.CAID, profile.Name, profile.Description,
		int64(profile.DefaultValidity.Seconds()), int64(profile.MaxValidity.Seconds()), profile.KeyUsages,
		profile.ExtendedKeyUsages, profile.AllowedDNSPatterns, profile.AllowedIPRanges,
		profile.AllowEmailSANs, profile.AllowURISANs, jsonOrEmpty(profile.Policy, `{}`), profile.Enabled)
	return scanProfile(row)
}

func (s *Store) UpdateProfile(ctx context.Context, profile SigningProfile) (SigningProfile, error) {
	row := s.pool.QueryRow(ctx, `UPDATE signing_profiles SET name=$3,description=$4,
        default_validity=make_interval(secs=>$5),max_validity=make_interval(secs=>$6),key_usages=$7,
        extended_key_usages=$8,allowed_dns_patterns=$9,allowed_ip_ranges=$10::cidr[],
        allow_email_sans=$11,allow_uri_sans=$12,policy=$13,enabled=$14,updated_at=now()
        WHERE id=$1 AND ca_id=$2 RETURNING `+profileColumns, profile.ID, profile.CAID, profile.Name,
		profile.Description, int64(profile.DefaultValidity.Seconds()), int64(profile.MaxValidity.Seconds()),
		profile.KeyUsages, profile.ExtendedKeyUsages, profile.AllowedDNSPatterns, profile.AllowedIPRanges,
		profile.AllowEmailSANs, profile.AllowURISANs, jsonOrEmpty(profile.Policy, `{}`), profile.Enabled)
	return scanProfile(row)
}

func (s *Store) DeleteProfile(ctx context.Context, caID, profileID string) error {
	command, err := s.pool.Exec(ctx, `DELETE FROM signing_profiles WHERE id=$1 AND ca_id=$2 AND name<>'default'`, profileID, caID)
	if err == nil && command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) CreateCertificateRequest(ctx context.Context, req CertificateRequest) (CertificateRequest, error) {
	var validity any
	if req.RequestedValiditySecs != nil {
		validity = *req.RequestedValiditySecs
	}
	row := s.pool.QueryRow(ctx, `INSERT INTO certificate_requests
        (requester_id,ca_id,profile_id,csr_pem,requested_subject,requested_sans,key_generation_mode,requested_validity)
        VALUES ($1,$2,$3,$4,$5,$6,$7,CASE WHEN $8::bigint IS NULL THEN NULL ELSE make_interval(secs=>$8) END)
        RETURNING `+requestColumns, req.RequesterID, req.CAID, req.ProfileID, req.CSRPEM,
		req.RequestedSubject, req.RequestedSANs, req.KeyGenerationMode, validity)
	return scanRequest(row)
}

const requestColumns = `id::text,requester_id::text,ca_id::text,profile_id::text,csr_pem,
requested_subject,requested_sans,key_generation_mode,
CASE WHEN requested_validity IS NULL THEN NULL ELSE extract(epoch from requested_validity)::bigint END,
status,rejection_reason,error_code,submitted_at,approved_at,issued_at`

func scanRequest(row pgx.Row) (CertificateRequest, error) {
	var req CertificateRequest
	err := row.Scan(&req.ID, &req.RequesterID, &req.CAID, &req.ProfileID, &req.CSRPEM,
		&req.RequestedSubject, &req.RequestedSANs, &req.KeyGenerationMode,
		&req.RequestedValiditySecs, &req.Status, &req.RejectionReason, &req.ErrorCode,
		&req.SubmittedAt, &req.ApprovedAt, &req.IssuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CertificateRequest{}, ErrNotFound
	}
	return req, err
}

func (s *Store) RequestByID(ctx context.Context, id string) (CertificateRequest, error) {
	return scanRequest(s.pool.QueryRow(ctx, `SELECT `+requestColumns+` FROM certificate_requests WHERE id=$1`, id))
}

func (s *Store) ListRequests(ctx context.Context, actor User) ([]CertificateRequest, error) {
	query := `SELECT ` + requestColumns + ` FROM certificate_requests r WHERE r.requester_id=$1`
	args := []any{actor.ID}
	if actor.Role == "super_admin" {
		query = `SELECT ` + requestColumns + ` FROM certificate_requests r WHERE true`
		args = nil
	} else if actor.Role == "operator" {
		query = `SELECT ` + requestColumns + ` FROM certificate_requests r
		  WHERE r.requester_id=$1
		     OR EXISTS (SELECT 1 FROM request_approvals a WHERE a.request_id=r.id AND a.approver_id=$1)
		     OR EXISTS (SELECT 1 FROM ca_grants g WHERE g.ca_id=r.ca_id AND g.user_id=$1
		                AND g.permission IN ('view_requests','approve','issue','revoke'))`
	}
	rows, err := s.pool.Query(ctx, query+` ORDER BY submitted_at DESC,id DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertificateRequest
	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	return out, rows.Err()
}

func (s *Store) DecideRequest(ctx context.Context, requestID string, actor User, decision, comment string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var requesterID, caID, status string
	if err = tx.QueryRow(ctx, `SELECT requester_id::text,ca_id::text,status FROM certificate_requests WHERE id=$1 FOR UPDATE`, requestID).
		Scan(&requesterID, &caID, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status != "pending" {
		return errors.New("certificate request is no longer pending")
	}
	if requesterID == actor.ID {
		return errors.New("requesters cannot approve their own request")
	}
	if actor.Role != "super_admin" {
		var allowed bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ca_grants
            WHERE ca_id=$1 AND user_id=$2 AND permission='approve')`, caID, actor.ID).Scan(&allowed)
		if err != nil || !allowed {
			return errors.New("operator is not authorized for this CA")
		}
	}
	if decision != "approved" && decision != "rejected" {
		return errors.New("decision must be approved or rejected")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO request_approvals(request_id,approver_id,decision,comment)
        VALUES ($1,$2,$3,$4)`, requestID, actor.ID, decision, comment); err != nil {
		return err
	}
	if decision == "approved" {
		if _, err = tx.Exec(ctx, `UPDATE certificate_requests SET status='approved',approved_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, requestID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO issuance_jobs(request_id) VALUES ($1)`, requestID); err != nil {
			return err
		}
	} else {
		_, err = tx.Exec(ctx, `UPDATE certificate_requests SET status='rejected',rejection_reason=$2,updated_at=now(),version=version+1 WHERE id=$1`, requestID, comment)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ClaimIssuanceJob(ctx context.Context, worker string) (string, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)
	var jobID, requestID string
	err = tx.QueryRow(ctx, `SELECT j.id::text,j.request_id::text FROM issuance_jobs j
        JOIN certificate_requests r ON r.id=j.request_id
        WHERE r.status IN ('approved','issuing') AND (
          (j.status IN ('queued','failed') AND j.next_attempt_at<=now()) OR
          (j.status='running' AND j.locked_at<now()-interval '5 minutes'))
        ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1`).Scan(&jobID, &requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE issuance_jobs SET status='running',attempt_count=attempt_count+1,
        locked_by=$2,locked_at=now(),updated_at=now() WHERE id=$1`, jobID, worker); err != nil {
		return "", "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE certificate_requests SET status='issuing',updated_at=now(),version=version+1 WHERE id=$1 AND status IN ('approved','issuing')`, requestID); err != nil {
		return "", "", err
	}
	return jobID, requestID, tx.Commit(ctx)
}

type KeyArtifact struct {
	EncryptedPKCS8    []byte
	Nonce             []byte
	KEKID             string
	DownloadTokenHash []byte
	ExpiresAt         time.Time
}

func (s *Store) ConsumeLeafKeyArtifact(ctx context.Context, certificateID, ownerUserID string, now time.Time, validate func(KeyArtifact) error) (KeyArtifact, error) {
	if validate == nil {
		return KeyArtifact{}, errors.New("key artifact validation is required")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return KeyArtifact{}, err
	}
	defer tx.Rollback(ctx)
	var artifact KeyArtifact
	err = tx.QueryRow(ctx, `SELECT a.encrypted_pkcs8,a.nonce,a.kek_id,a.download_token_hash,a.expires_at
        FROM leaf_key_artifacts a JOIN certificates c ON c.id=a.certificate_id
        WHERE a.certificate_id=$1 AND c.owner_user_id=$2 AND a.downloaded_at IS NULL
          AND a.erased_at IS NULL AND a.expires_at>$3 FOR UPDATE`, certificateID, ownerUserID, now).
		Scan(&artifact.EncryptedPKCS8, &artifact.Nonce, &artifact.KEKID, &artifact.DownloadTokenHash, &artifact.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return KeyArtifact{}, ErrNotFound
	}
	if err != nil {
		return KeyArtifact{}, err
	}
	if err := validate(artifact); err != nil {
		return KeyArtifact{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE leaf_key_artifacts SET downloaded_at=$2,erased_at=$2,
        encrypted_pkcs8=$3,nonce=$4 WHERE certificate_id=$1`, certificateID, now,
		[]byte{}, make([]byte, 12))
	if err != nil {
		return KeyArtifact{}, err
	}
	return artifact, tx.Commit(ctx)
}

func (s *Store) CompleteIssuance(ctx context.Context, jobID, owner string, cert Certificate, artifact *KeyArtifact) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var requestID, requesterID string
	err = tx.QueryRow(ctx, `SELECT j.request_id::text,r.requester_id::text
        FROM issuance_jobs j JOIN certificate_requests r ON r.id=j.request_id
        WHERE j.id=$1 AND j.status='running' AND j.locked_by=$2 AND r.status='issuing'
        FOR UPDATE OF j,r`, jobID, owner).Scan(&requestID, &requesterID)
	if err != nil {
		return err
	}
	if cert.RequestID == nil || *cert.RequestID != requestID || cert.OwnerUserID != requesterID {
		return errors.New("issuance result does not match claimed request")
	}
	var activeUser string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM users WHERE id=$1 AND status='active' FOR SHARE`, requesterID).Scan(&activeUser); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO certificates
        (id,issuer_ca_id,owner_user_id,request_id,profile_id,serial,aki,ski,fingerprint_sha256,
         certificate_pem,chain_pem,subject,sans,key_usages,extended_key_usages,not_before,not_after,status)
        SELECT $1,$2,$3,$4,profile_id,$5::numeric,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'good'
        FROM certificate_requests WHERE id=$4`, cert.ID, cert.IssuerCAID, cert.OwnerUserID,
		cert.RequestID, cert.Serial, cert.AKI, nullableBytes(cert.SKI), cert.FingerprintSHA256,
		cert.CertificatePEM, cert.ChainPEM, cert.Subject, cert.SANs, []string{}, []string{},
		cert.NotBefore, cert.NotAfter)
	if err != nil {
		return err
	}
	if artifact != nil {
		_, err = tx.Exec(ctx, `INSERT INTO leaf_key_artifacts
            (certificate_id,encrypted_pkcs8,nonce,kek_id,download_token_hash,expires_at)
            VALUES ($1,$2,$3,$4,$5,$6)`, cert.ID, artifact.EncryptedPKCS8, artifact.Nonce,
			artifact.KEKID, artifact.DownloadTokenHash, artifact.ExpiresAt)
		if err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE certificate_requests SET status='issued',issued_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, cert.RequestID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE issuance_jobs SET status='succeeded',locked_by=NULL,locked_at=NULL,updated_at=now() WHERE id=$1`, jobID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FailIssuance(ctx context.Context, jobID, requestID, owner, code string, retry bool) error {
	status := "failed"
	next := time.Now().Add(5 * time.Minute)
	if !retry {
		next = time.Now().Add(100 * 365 * 24 * time.Hour)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `UPDATE issuance_jobs SET status=$2,last_error_code=$3,
        next_attempt_at=$4,locked_by=NULL,locked_at=NULL,updated_at=now()
        WHERE id=$1 AND request_id=$5 AND status='running' AND locked_by=$6`, jobID, status, code, next, requestID, owner)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrNotFound
	}
	requestStatus := "failed"
	if retry {
		requestStatus = "approved"
	}
	_, err = tx.Exec(ctx, `UPDATE certificate_requests SET status=$3,error_code=$2,updated_at=now(),version=version+1 WHERE id=$1 AND status='issuing'`, requestID, code, requestStatus)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const certificateColumns = `id::text,issuer_ca_id::text,owner_user_id::text,request_id::text,
serial::text,fingerprint_sha256,certificate_pem,chain_pem,subject,sans,not_before,not_after,status,created_at`

func scanCertificate(row pgx.Row) (Certificate, error) {
	var cert Certificate
	err := row.Scan(&cert.ID, &cert.IssuerCAID, &cert.OwnerUserID, &cert.RequestID,
		&cert.Serial, &cert.FingerprintSHA256, &cert.CertificatePEM, &cert.ChainPEM,
		&cert.Subject, &cert.SANs, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	return cert, err
}

func (s *Store) CertificateByID(ctx context.Context, id string) (Certificate, error) {
	return scanCertificate(s.pool.QueryRow(ctx, `SELECT `+certificateColumns+` FROM certificates WHERE id=$1`, id))
}

func (s *Store) CertificateByFingerprint(ctx context.Context, fingerprint []byte) (Certificate, error) {
	return scanCertificate(s.pool.QueryRow(ctx, `SELECT `+certificateColumns+` FROM certificates WHERE fingerprint_sha256=$1`, fingerprint))
}

func (s *Store) CertificateByIssuerSerial(ctx context.Context, caID, serial string) (Certificate, error) {
	return scanCertificate(s.pool.QueryRow(ctx, `SELECT `+certificateColumns+` FROM certificates WHERE issuer_ca_id=$1 AND serial=$2::numeric`, caID, serial))
}

func (s *Store) ListCertificates(ctx context.Context, actor User) ([]Certificate, error) {
	query := `SELECT ` + certificateColumns + ` FROM certificates WHERE owner_user_id=$1`
	args := []any{actor.ID}
	if actor.Role == "super_admin" {
		query = `SELECT ` + certificateColumns + ` FROM certificates WHERE true`
		args = nil
	} else if actor.Role == "operator" {
		query = `SELECT ` + certificateColumns + ` FROM certificates c
		  WHERE c.owner_user_id=$1
		     OR EXISTS (SELECT 1 FROM request_approvals a WHERE a.request_id=c.request_id
		                AND a.approver_id=$1 AND a.decision='approved')
		     OR EXISTS (SELECT 1 FROM ca_grants g WHERE g.ca_id=c.issuer_ca_id AND g.user_id=$1
		                AND g.permission IN ('view_requests','approve','issue','revoke'))`
	}
	rows, err := s.pool.Query(ctx, query+` ORDER BY created_at DESC,id DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	return out, rows.Err()
}

func (s *Store) ListCertificateInventory(ctx context.Context, actor User, workflowStatus string) ([]CertificateInventoryItem, error) {
	query := `WITH inventory AS (
		SELECT r.id::text AS request_id,c.id::text AS certificate_id,r.requester_id::text AS owner_user_id,
		       requester.username AS requester_username,r.ca_id::text AS issuer_ca_id,ca.name AS issuer_name,
		       ca.slug AS issuer_slug,COALESCE(c.subject,r.requested_subject) AS subject,
		       COALESCE(c.sans,r.requested_sans) AS sans,
		       CASE WHEN r.status IN ('pending','approved','issuing') THEN 'pending'
		            WHEN r.status='issued' THEN 'issued' WHEN r.status='rejected' THEN 'rejected'
		            ELSE 'failed' END AS workflow_status,
		       r.status AS request_status,c.status AS certificate_status,c.serial::text AS serial,
		       r.rejection_reason,r.error_code,a.approver_id::text AS approver_id,
		       approver.username AS approver_username,r.submitted_at,r.approved_at,r.issued_at,
		       c.not_before,c.not_after
		FROM certificate_requests r
		JOIN users requester ON requester.id=r.requester_id
		JOIN certificate_authorities ca ON ca.id=r.ca_id
		LEFT JOIN certificates c ON c.request_id=r.id
		LEFT JOIN request_approvals a ON a.request_id=r.id
		LEFT JOIN users approver ON approver.id=a.approver_id
		UNION ALL
		SELECT NULL::text,c.id::text,c.owner_user_id::text,owner.username,c.issuer_ca_id::text,ca.name,ca.slug,
		       c.subject,c.sans,'issued',NULL::text,c.status,c.serial::text,NULL::text,NULL::text,
		       NULL::text,NULL::text,c.created_at,NULL::timestamptz,c.created_at,c.not_before,c.not_after
		FROM certificates c
		JOIN users owner ON owner.id=c.owner_user_id
		JOIN certificate_authorities ca ON ca.id=c.issuer_ca_id
		WHERE c.request_id IS NULL
	)
	SELECT request_id,certificate_id,owner_user_id,requester_username,issuer_ca_id,issuer_name,issuer_slug,
	       subject,sans,workflow_status,request_status,certificate_status,serial,rejection_reason,error_code,
	       approver_id,approver_username,submitted_at,approved_at,issued_at,not_before,not_after
	FROM inventory i WHERE true`
	args := []any{}
	if actor.Role != "super_admin" {
		args = append(args, actor.ID)
		actorArg := len(args)
		if actor.Role == "operator" {
			query += fmt.Sprintf(` AND (i.owner_user_id=$%d OR i.approver_id=$%d OR EXISTS
			  (SELECT 1 FROM ca_grants g WHERE g.ca_id=i.issuer_ca_id::uuid AND g.user_id::text=$%d
			   AND g.permission IN ('view_requests','approve','issue','revoke')))`, actorArg, actorArg, actorArg)
		} else {
			query += fmt.Sprintf(` AND i.owner_user_id=$%d`, actorArg)
		}
	}
	if workflowStatus != "" {
		args = append(args, workflowStatus)
		query += fmt.Sprintf(` AND i.workflow_status=$%d`, len(args))
	}
	rows, err := s.pool.Query(ctx, query+` ORDER BY COALESCE(issued_at,submitted_at) DESC,COALESCE(certificate_id,request_id) DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertificateInventoryItem
	for rows.Next() {
		var item CertificateInventoryItem
		if err := rows.Scan(&item.RequestID, &item.CertificateID, &item.OwnerUserID, &item.RequesterUsername,
			&item.IssuerCAID, &item.IssuerName, &item.IssuerSlug, &item.Subject, &item.SANs,
			&item.WorkflowStatus, &item.RequestStatus, &item.CertificateStatus, &item.Serial,
			&item.RejectionReason, &item.ErrorCode, &item.ApproverID, &item.ApproverUsername,
			&item.SubmittedAt, &item.ApprovedAt, &item.IssuedAt, &item.NotBefore, &item.NotAfter); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) OperatorCanViewCertificate(ctx context.Context, certificateID, userID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM certificates c WHERE c.id=$1 AND (
			c.owner_user_id=$2 OR
			EXISTS (SELECT 1 FROM request_approvals a WHERE a.request_id=c.request_id
			        AND a.approver_id=$2 AND a.decision='approved') OR
			EXISTS (SELECT 1 FROM ca_grants g WHERE g.ca_id=c.issuer_ca_id AND g.user_id=$2
			        AND g.permission IN ('view_requests','approve','issue','revoke'))
		))`, certificateID, userID).Scan(&allowed)
	return allowed, err
}

type RevokedCertificate struct {
	Serial    string
	RevokedAt time.Time
	Reason    int
}

func (s *Store) RevocationForCertificate(ctx context.Context, certificateID string) (RevokedCertificate, error) {
	var item RevokedCertificate
	err := s.pool.QueryRow(ctx, `SELECT c.serial::text,r.revoked_at,r.reason FROM certificates c
        JOIN revocations r ON r.certificate_id=c.id WHERE c.id=$1`, certificateID).
		Scan(&item.Serial, &item.RevokedAt, &item.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return RevokedCertificate{}, ErrNotFound
	}
	return item, err
}

func (s *Store) RevokeCertificate(ctx context.Context, certificateID string, actor User, reason int, comment string) (Certificate, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Certificate{}, err
	}
	defer tx.Rollback(ctx)
	cert, err := scanCertificate(tx.QueryRow(ctx, `SELECT `+certificateColumns+` FROM certificates WHERE id=$1 FOR UPDATE`, certificateID))
	if err != nil {
		return Certificate{}, err
	}
	if cert.Status == "revoked" {
		return Certificate{}, errors.New("certificate is already revoked")
	}
	if actor.Role != "super_admin" {
		var allowed bool
		if actor.Role == "operator" {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ca_grants WHERE ca_id=$1 AND user_id=$2 AND permission='revoke')`, cert.IssuerCAID, actor.ID).Scan(&allowed)
		}
		if err != nil || !allowed {
			return Certificate{}, errors.New("actor is not authorized to revoke this certificate")
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO revocations(certificate_id,reason,revoked_by,comment) VALUES ($1,$2,$3,$4)`, certificateID, reason, actor.ID, comment); err != nil {
		return Certificate{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE certificates SET status='revoked' WHERE id=$1`, certificateID); err != nil {
		return Certificate{}, err
	}
	cert.Status = "revoked"
	return cert, tx.Commit(ctx)
}

func (s *Store) RevokedCertificates(ctx context.Context, caID string) ([]RevokedCertificate, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.serial::text,r.revoked_at,r.reason FROM certificates c
        JOIN revocations r ON r.certificate_id=c.id WHERE c.issuer_ca_id=$1 AND c.not_after>now()
        ORDER BY c.serial`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokedCertificate
	for rows.Next() {
		var item RevokedCertificate
		if err := rows.Scan(&item.Serial, &item.RevokedAt, &item.Reason); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// RefreshCRL serializes the revocation snapshot, signature and publication for
// one CA across all processes. An older snapshot cannot overwrite a newer CRL.
func (s *Store) RefreshCRL(ctx context.Context, caID string, generate func([]RevokedCertificate, int64) ([]byte, time.Time, time.Time, error)) ([]byte, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "crl:"+caID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT c.serial::text,r.revoked_at,r.reason FROM certificates c
        JOIN revocations r ON r.certificate_id=c.id WHERE c.issuer_ca_id=$1 AND c.not_after>now() ORDER BY c.serial`, caID)
	if err != nil {
		return nil, err
	}
	var revoked []RevokedCertificate
	for rows.Next() {
		var cert RevokedCertificate
		if err := rows.Scan(&cert.Serial, &cert.RevokedAt, &cert.Reason); err != nil {
			rows.Close()
			return nil, err
		}
		revoked = append(revoked, cert)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var number int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(crl_number)+1,1) FROM crls WHERE ca_id=$1`, caID).Scan(&number); err != nil {
		return nil, err
	}
	der, thisUpdate, nextUpdate, err := generate(revoked, number)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(der)
	if _, err = tx.Exec(ctx, `UPDATE crls SET is_current=false WHERE ca_id=$1 AND is_current`, caID); err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO crls(ca_id,crl_number,der,sha256,this_update,next_update)
        VALUES ($1,$2,$3,$4,$5,$6)`, caID, number, der, digest[:], thisUpdate, nextUpdate)
	if err != nil {
		return nil, err
	}
	return der, tx.Commit(ctx)
}

func (s *Store) CurrentCRL(ctx context.Context, caID string) ([]byte, time.Time, error) {
	var der []byte
	var next time.Time
	err := s.pool.QueryRow(ctx, `SELECT der,next_update FROM crls WHERE ca_id=$1 AND is_current`, caID).Scan(&der, &next)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	return der, next, err
}

func (s *Store) SaveOCSPResponse(ctx context.Context, certificateID, responderID, status string,
	reason int, revokedAt *time.Time, der []byte, producedAt, thisUpdate, nextUpdate time.Time) error {
	var reasonValue any
	if status == "revoked" {
		reasonValue = reason
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO ocsp_responses
        (certificate_id,responder_id,status,revocation_reason,revoked_at,der,produced_at,this_update,next_update)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        ON CONFLICT (certificate_id) DO UPDATE SET responder_id=EXCLUDED.responder_id,
        status=EXCLUDED.status,revocation_reason=EXCLUDED.revocation_reason,
        revoked_at=EXCLUDED.revoked_at,der=EXCLUDED.der,produced_at=EXCLUDED.produced_at,
        this_update=EXCLUDED.this_update,next_update=EXCLUDED.next_update`, certificateID,
		responderID, status, reasonValue, revokedAt, der, producedAt, thisUpdate, nextUpdate)
	return err
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func jsonOrEmpty(value json.RawMessage, fallback string) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(fallback)
	}
	return value
}
