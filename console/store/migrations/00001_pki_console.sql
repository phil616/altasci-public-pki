-- +goose Up

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    username text NOT NULL,
    email text,
    role text NOT NULL CHECK (role IN ('super_admin', 'operator', 'user')),
    password_hash text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'locked')),
    failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until timestamptz,
    root_totp_last_step bigint NOT NULL DEFAULT 0,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1,
    CHECK (role <> 'super_admin' OR email IS NOT NULL)
);
CREATE UNIQUE INDEX users_username_lower_uq ON users (lower(username));
CREATE UNIQUE INDEX users_email_lower_uq ON users (lower(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_single_super_admin_uq ON users (role) WHERE role = 'super_admin';

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    ip inet,
    user_agent text NOT NULL DEFAULT '',
    CHECK (idle_expires_at <= absolute_expires_at)
);
CREATE INDEX sessions_user_active_idx ON sessions (user_id, idle_expires_at) WHERE revoked_at IS NULL;

CREATE TABLE idempotency_keys (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope text NOT NULL,
    key text NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_code integer,
    response_body jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, scope, key)
);

CREATE TABLE certificate_authorities (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    parent_ca_id uuid REFERENCES certificate_authorities(id),
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('root', 'intermediate')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'suspended', 'retired', 'revoked', 'destroyed')),
    subject jsonb NOT NULL,
    serial numeric(50,0) NOT NULL CHECK (serial > 0),
    ski bytea NOT NULL,
    aki bytea,
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    path_length integer NOT NULL DEFAULT 0 CHECK (path_length >= 0),
    crl_url text,
    ocsp_url text,
    issuer_url text,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((kind = 'root' AND parent_ca_id IS NULL) OR (kind = 'intermediate' AND parent_ca_id IS NOT NULL)),
    CHECK (not_after > not_before),
    UNIQUE (id, kind),
    UNIQUE (id, serial)
);

CREATE TABLE ca_key_versions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    ca_id uuid NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
    version integer NOT NULL CHECK (version > 0),
    algorithm text NOT NULL CHECK (algorithm IN ('RSA-4096', 'RSA-3072', 'ECDSA-P384', 'ECDSA-P256')),
    public_key_fingerprint bytea NOT NULL CHECK (octet_length(public_key_fingerprint) = 32),
    encrypted_pkcs8 bytea NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    kek_id text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'destroyed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    UNIQUE (ca_id, version)
);
CREATE UNIQUE INDEX ca_key_versions_active_uq ON ca_key_versions (ca_id) WHERE status = 'active';

CREATE TABLE ocsp_responders (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    ca_id uuid NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
    certificate_pem text NOT NULL,
    encrypted_pkcs8 bytea NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    kek_id text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ocsp_responder_active_uq ON ocsp_responders (ca_id) WHERE status = 'active';

CREATE TABLE signing_profiles (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    ca_id uuid NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    default_validity interval NOT NULL DEFAULT interval '90 days',
    max_validity interval NOT NULL DEFAULT interval '397 days',
    key_usages text[] NOT NULL,
    extended_key_usages text[] NOT NULL DEFAULT '{}',
    allowed_dns_patterns text[] NOT NULL DEFAULT '{}',
    allowed_ip_ranges cidr[] NOT NULL DEFAULT '{}',
    allow_email_sans boolean NOT NULL DEFAULT false,
    allow_uri_sans boolean NOT NULL DEFAULT false,
    policy jsonb NOT NULL DEFAULT '{}',
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (default_validity > interval '0 seconds'),
    CHECK (max_validity >= default_validity),
    UNIQUE (ca_id, name)
);

CREATE TABLE ca_grants (
    ca_id uuid NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission text NOT NULL CHECK (permission IN ('view_requests', 'approve', 'issue', 'revoke')),
    granted_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ca_id, user_id, permission)
);

-- +goose StatementBegin
CREATE FUNCTION reject_root_ca_grant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM certificate_authorities WHERE id = NEW.ca_id AND kind = 'root') THEN
        RAISE EXCEPTION 'root CA permissions cannot be delegated';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id AND role = 'operator' AND status = 'active') THEN
        RAISE EXCEPTION 'CA grants may only target active operators';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER ca_grants_validate BEFORE INSERT OR UPDATE ON ca_grants
FOR EACH ROW EXECUTE FUNCTION reject_root_ca_grant();

CREATE TABLE certificate_requests (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    requester_id uuid NOT NULL REFERENCES users(id),
    ca_id uuid NOT NULL REFERENCES certificate_authorities(id),
    profile_id uuid NOT NULL REFERENCES signing_profiles(id),
    csr_pem text,
    requested_subject jsonb NOT NULL,
    requested_sans jsonb NOT NULL DEFAULT '[]',
    key_generation_mode text NOT NULL CHECK (key_generation_mode IN ('client_csr', 'server_generated')),
    requested_validity interval,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'issuing', 'issued', 'rejected', 'failed', 'cancelled')),
    rejection_reason text,
    error_code text,
    submitted_at timestamptz NOT NULL DEFAULT now(),
    approved_at timestamptz,
    issued_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1,
    CHECK ((key_generation_mode = 'client_csr' AND csr_pem IS NOT NULL) OR key_generation_mode = 'server_generated')
);
CREATE INDEX certificate_requests_queue_idx ON certificate_requests (status, submitted_at);
CREATE INDEX certificate_requests_owner_idx ON certificate_requests (requester_id, submitted_at DESC);

CREATE TABLE request_approvals (
    request_id uuid PRIMARY KEY REFERENCES certificate_requests(id) ON DELETE CASCADE,
    approver_id uuid NOT NULL REFERENCES users(id),
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    comment text NOT NULL DEFAULT '',
    decided_at timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION reject_self_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM certificate_requests WHERE id = NEW.request_id AND requester_id = NEW.approver_id) THEN
        RAISE EXCEPTION 'requesters cannot approve their own certificate requests';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER request_approvals_no_self BEFORE INSERT OR UPDATE ON request_approvals
FOR EACH ROW EXECUTE FUNCTION reject_self_approval();

CREATE TABLE issuance_jobs (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    request_id uuid NOT NULL UNIQUE REFERENCES certificate_requests(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_by text,
    locked_at timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX issuance_jobs_ready_idx ON issuance_jobs (next_attempt_at, created_at) WHERE status IN ('queued', 'failed');

CREATE TABLE certificates (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    issuer_ca_id uuid NOT NULL REFERENCES certificate_authorities(id),
    owner_user_id uuid NOT NULL REFERENCES users(id),
    request_id uuid UNIQUE REFERENCES certificate_requests(id),
    profile_id uuid REFERENCES signing_profiles(id),
    serial numeric(50,0) NOT NULL CHECK (serial > 0),
    aki bytea NOT NULL,
    ski bytea,
    fingerprint_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(fingerprint_sha256) = 32),
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    subject jsonb NOT NULL,
    sans jsonb NOT NULL DEFAULT '[]',
    key_usages text[] NOT NULL DEFAULT '{}',
    extended_key_usages text[] NOT NULL DEFAULT '{}',
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'good' CHECK (status IN ('good', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (not_after > not_before),
    UNIQUE (issuer_ca_id, serial)
);
CREATE INDEX certificates_owner_idx ON certificates (owner_user_id, created_at DESC);
CREATE INDEX certificates_issuer_status_idx ON certificates (issuer_ca_id, status, not_after);

CREATE TABLE leaf_key_artifacts (
    certificate_id uuid PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE,
    encrypted_pkcs8 bytea NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    kek_id text NOT NULL,
    download_token_hash bytea NOT NULL UNIQUE CHECK (octet_length(download_token_hash) = 32),
    expires_at timestamptz NOT NULL,
    downloaded_at timestamptz,
    erased_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE revocations (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    certificate_id uuid NOT NULL UNIQUE REFERENCES certificates(id),
    reason smallint NOT NULL CHECK (reason BETWEEN 0 AND 10 AND reason <> 7),
    invalidity_date timestamptz,
    revoked_by uuid NOT NULL REFERENCES users(id),
    comment text NOT NULL DEFAULT '',
    revoked_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE crls (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    ca_id uuid NOT NULL REFERENCES certificate_authorities(id),
    crl_number bigint NOT NULL CHECK (crl_number > 0),
    der bytea NOT NULL,
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    this_update timestamptz NOT NULL,
    next_update timestamptz NOT NULL,
    is_current boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (next_update > this_update),
    UNIQUE (ca_id, crl_number)
);
CREATE UNIQUE INDEX crls_current_uq ON crls (ca_id) WHERE is_current;

CREATE TABLE ocsp_responses (
    certificate_id uuid PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE,
    responder_id uuid REFERENCES ocsp_responders(id),
    status text NOT NULL CHECK (status IN ('good', 'revoked', 'unknown')),
    revocation_reason smallint,
    revoked_at timestamptz,
    der bytea NOT NULL,
    produced_at timestamptz NOT NULL,
    this_update timestamptz NOT NULL,
    next_update timestamptz NOT NULL,
    CHECK (next_update > this_update)
);
CREATE INDEX ocsp_responses_expiry_idx ON ocsp_responses (next_update);

CREATE TABLE audit_chain_heads (
    scope text PRIMARY KEY,
    head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id uuid NOT NULL DEFAULT uuidv7(),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_user_id uuid REFERENCES users(id),
    actor_role text,
    session_id uuid,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text,
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    request_id text NOT NULL,
    source_ip inet,
    user_agent text NOT NULL DEFAULT '',
    cf_access_sub text,
    before_state jsonb,
    after_state jsonb,
    metadata jsonb NOT NULL DEFAULT '{}',
    prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;
CREATE INDEX audit_events_actor_idx ON audit_events (actor_user_id, occurred_at DESC);
CREATE INDEX audit_events_resource_idx ON audit_events (resource_type, resource_id, occurred_at DESC);
CREATE UNIQUE INDEX audit_events_hash_uq ON audit_events (occurred_at, event_hash);

-- +goose StatementBegin
CREATE FUNCTION deny_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END $$;
-- +goose StatementEnd
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION deny_audit_mutation();

-- +goose StatementBegin
CREATE FUNCTION pki_create_audit_partition(month_start date) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    partition_name text := 'audit_events_' || to_char(month_start, 'YYYY_MM');
    month_end date := (month_start + interval '1 month')::date;
BEGIN
    EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
                   partition_name, month_start, month_end);
END $$;
-- +goose StatementEnd

SELECT pki_create_audit_partition(date_trunc('month', current_date)::date);

-- +goose Down
DROP FUNCTION IF EXISTS pki_create_audit_partition(date);
DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS audit_chain_heads;
DROP TABLE IF EXISTS ocsp_responses;
DROP TABLE IF EXISTS crls;
DROP TABLE IF EXISTS revocations;
DROP TABLE IF EXISTS leaf_key_artifacts;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS issuance_jobs;
DROP TRIGGER IF EXISTS request_approvals_no_self ON request_approvals;
DROP FUNCTION IF EXISTS reject_self_approval();
DROP TABLE IF EXISTS request_approvals;
DROP TABLE IF EXISTS certificate_requests;
DROP TRIGGER IF EXISTS ca_grants_validate ON ca_grants;
DROP FUNCTION IF EXISTS reject_root_ca_grant();
DROP TABLE IF EXISTS ca_grants;
DROP TABLE IF EXISTS signing_profiles;
DROP TABLE IF EXISTS ocsp_responders;
DROP TABLE IF EXISTS ca_key_versions;
DROP TABLE IF EXISTS certificate_authorities;
DROP TABLE IF EXISTS idempotency_keys;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
