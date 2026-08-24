-- +goose Up

CREATE TABLE timestamp_authorities (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    ca_id uuid NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name text NOT NULL,
    policy_oid text NOT NULL CHECK (policy_oid ~ '^[0-2](\.[0-9]+)+$'),
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    encrypted_pkcs8 bytea NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    kek_id text NOT NULL,
    allowed_hashes text[] NOT NULL DEFAULT ARRAY['SHA-256', 'SHA-384', 'SHA-512']::text[],
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'retired', 'revoked')),
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (not_after > not_before),
    CHECK (cardinality(allowed_hashes) > 0),
    CHECK (allowed_hashes <@ ARRAY['SHA-256', 'SHA-384', 'SHA-512']::text[])
);
CREATE INDEX timestamp_authorities_ca_idx ON timestamp_authorities (ca_id, created_at DESC);

CREATE TABLE timestamp_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    tsa_id uuid NOT NULL REFERENCES timestamp_authorities(id) ON DELETE RESTRICT,
    serial numeric(50,0) NOT NULL CHECK (serial > 0),
    hash_algorithm text NOT NULL CHECK (hash_algorithm IN ('SHA-256', 'SHA-384', 'SHA-512')),
    message_imprint bytea NOT NULL CHECK (octet_length(message_imprint) IN (32, 48, 64)),
    policy_oid text NOT NULL,
    nonce text,
    generated_at timestamptz NOT NULL,
    accuracy_micros bigint NOT NULL CHECK (accuracy_micros >= 0),
    token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256) = 32),
    token_der bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT timestamp_tokens_tsa_serial_uq UNIQUE (tsa_id, serial),
    UNIQUE (token_sha256)
);
CREATE INDEX timestamp_tokens_tsa_time_idx ON timestamp_tokens (tsa_id, generated_at DESC);
CREATE INDEX timestamp_tokens_imprint_idx ON timestamp_tokens (hash_algorithm, message_imprint);

-- +goose Down
DROP TABLE IF EXISTS timestamp_tokens;
DROP TABLE IF EXISTS timestamp_authorities;
