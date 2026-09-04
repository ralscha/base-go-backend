-- +goose Up
ALTER TABLE users
ADD COLUMN auth_version BIGINT NOT NULL DEFAULT 1,
ADD COLUMN last_failed_login_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE users
DROP COLUMN last_failed_login_at,
DROP COLUMN auth_version;
