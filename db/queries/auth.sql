-- name: UpsertPasswordCredential :one
INSERT INTO password_credentials (
    user_id,
    password_hash
) VALUES (
    $1,
    $2
)
ON CONFLICT (user_id)
DO UPDATE SET
    password_hash = EXCLUDED.password_hash
RETURNING *;

-- name: GetPasswordCredentialByUserID :one
SELECT *
FROM password_credentials
WHERE user_id = $1;

-- name: CreateUserToken :one
INSERT INTO user_tokens (
    user_id,
    kind,
    token_hash,
    expires_at
) VALUES (
    $1,
    $2,
    $3,
    $4
)
RETURNING *;

-- name: GetUserToken :one
SELECT *
FROM user_tokens
WHERE token_hash = $1
  AND kind = $2
  AND used_at IS NULL
  AND expires_at > NOW();

-- name: UseUserToken :exec
UPDATE user_tokens
SET used_at = NOW()
WHERE id = $1;

-- name: DeleteExpiredUserTokens :execrows
DELETE FROM user_tokens
WHERE used_at IS NOT NULL
   OR expires_at < NOW();

-- name: InsertLoginAttempt :one
INSERT INTO login_attempts (
    user_id,
    username,
    success,
    ip_address,
    user_agent
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
RETURNING *;

-- name: CountRecentFailedAttemptsByUser :one
SELECT COUNT(*)
FROM login_attempts
WHERE user_id = $1
  AND success = FALSE
  AND created_at >= $2;

-- name: CountRecentFailedAttemptsByUsername :one
SELECT COUNT(*)
FROM login_attempts
WHERE username = $1
  AND success = FALSE
  AND created_at >= $2;