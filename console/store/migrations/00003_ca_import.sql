-- +goose Up
ALTER TABLE ca_key_versions DROP CONSTRAINT ca_key_versions_algorithm_check;
ALTER TABLE ca_key_versions ADD CONSTRAINT ca_key_versions_algorithm_check
    CHECK (algorithm IN ('RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384'));
ALTER TABLE certificate_authorities DROP CONSTRAINT certificate_authorities_path_length_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_path_length_check CHECK (path_length >= -1);
CREATE UNIQUE INDEX certificate_authorities_certificate_uq
    ON certificate_authorities (sha256(certificate_pem::bytea));

-- +goose Down
-- Downgrade fails if incompatible imported CAs remain, rather than changing them.
DROP INDEX certificate_authorities_certificate_uq;
ALTER TABLE certificate_authorities DROP CONSTRAINT certificate_authorities_path_length_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_path_length_check CHECK (path_length >= 0);
ALTER TABLE ca_key_versions DROP CONSTRAINT ca_key_versions_algorithm_check;
ALTER TABLE ca_key_versions ADD CONSTRAINT ca_key_versions_algorithm_check
    CHECK (algorithm IN ('RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384'));
