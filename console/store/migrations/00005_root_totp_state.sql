-- +goose Up
-- Store only the secret fingerprint, never the authenticator secret itself.
ALTER TABLE users ADD COLUMN root_totp_secret_hash bytea
    CHECK (root_totp_secret_hash IS NULL OR octet_length(root_totp_secret_hash) = 32);

-- +goose Down
ALTER TABLE users DROP COLUMN root_totp_secret_hash;
