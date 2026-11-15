-- +goose Up
-- Isolated signing tools intentionally have no foreign key to the managed PKI.
CREATE TABLE signing_instances (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    owner_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    encrypted_key bytea NOT NULL,
    key_nonce bytea NOT NULL CHECK (octet_length(key_nonce)=12),
    kek_id text NOT NULL,
    policy jsonb NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    crl_der bytea,
    crl_next_update timestamptz,
    crl_number bigint NOT NULL DEFAULT 0 CHECK (crl_number>=0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX signing_instances_owner_idx ON signing_instances(owner_id, id);
CREATE TABLE signing_credentials (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    instance_id uuid NOT NULL REFERENCES signing_instances(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
    scopes text[] NOT NULL CHECK (cardinality(scopes)>0 AND scopes <@ ARRAY['issue','read','revoke']::text[]),
    policy jsonb,
    max_issuances integer NOT NULL CHECK (max_issuances BETWEEN 1 AND 1000000),
    issued_count integer NOT NULL DEFAULT 0 CHECK (issued_count>=0 AND issued_count<=max_issuances),
    rate_per_minute integer NOT NULL CHECK (rate_per_minute BETWEEN 1 AND 120),
    rate_window timestamptz NOT NULL DEFAULT now(),
    rate_count integer NOT NULL DEFAULT 0 CHECK (rate_count>=0),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(instance_id,id)
);
CREATE INDEX signing_credentials_instance_idx ON signing_credentials(instance_id,id);
CREATE TABLE signing_certificates (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    instance_id uuid NOT NULL REFERENCES signing_instances(id) ON DELETE RESTRICT,
    credential_id uuid NOT NULL,
    serial numeric(50,0) NOT NULL CHECK (serial>0),
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    fingerprint_sha256 text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash)=32),
    revoked_at timestamptz,
    revocation_reason integer CHECK (revocation_reason BETWEEN 0 AND 10 AND revocation_reason<>7 AND revocation_reason<>8),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(instance_id,credential_id) REFERENCES signing_credentials(instance_id,id) ON DELETE RESTRICT,
    UNIQUE(instance_id,serial),
    UNIQUE(credential_id,idempotency_key)
);
CREATE INDEX signing_certificates_instance_idx ON signing_certificates(instance_id,id);

-- +goose Down
-- Refuse destructive rollback when protected CA material or issuance history exists.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM signing_instances) THEN
        RAISE EXCEPTION 'independent signing data exists; export and handle it before downgrade';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE signing_certificates;
DROP TABLE signing_credentials;
DROP TABLE signing_instances;
