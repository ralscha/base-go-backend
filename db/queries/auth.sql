-- name: SetUserPasswordHash :one
UPDATE users
SET password_hash = $2
WHERE id = $1
RETURNING *;

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
WHERE expires_at < NOW()
    AND used_at IS NULL;

-- name: DeleteUsedUserTokens :execrows
DELETE FROM user_tokens
WHERE used_at IS NOT NULL;