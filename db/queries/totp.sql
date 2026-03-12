-- name: GetTotpConfigurationByUserID :one
SELECT *
FROM totp_configurations
WHERE user_id = $1;

-- name: UpsertTotpConfiguration :one
INSERT INTO totp_configurations (
    user_id,
    secret_ciphertext,
    secret_nonce,
    enabled_at
) VALUES (
    $1,
    $2,
    $3,
    $4
)
ON CONFLICT (user_id)
DO UPDATE SET
    secret_ciphertext = EXCLUDED.secret_ciphertext,
    secret_nonce = EXCLUDED.secret_nonce,
    enabled_at = EXCLUDED.enabled_at
RETURNING *;

-- name: EnableTotpConfiguration :exec
UPDATE totp_configurations
SET enabled_at = NOW()
WHERE user_id = $1;

-- name: DeleteTotpConfigurationByUserID :exec
DELETE FROM totp_configurations
WHERE user_id = $1;

-- name: DeleteTotpRecoveryCodesByUserID :exec
DELETE FROM totp_recovery_codes
WHERE user_id = $1;

-- name: CreateTotpRecoveryCode :one
INSERT INTO totp_recovery_codes (
    user_id,
    code_hash
) VALUES (
    $1,
    $2
)
RETURNING *;

-- name: ConsumeTotpRecoveryCode :execrows
UPDATE totp_recovery_codes
SET used_at = NOW()
WHERE user_id = $1
  AND code_hash = $2
  AND used_at IS NULL;