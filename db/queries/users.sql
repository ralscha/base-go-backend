-- name: CreateUser :one
INSERT INTO users (
    username,
    email
) VALUES (
    $1,
    $2
)
RETURNING *;

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1;

-- name: GetUserByUsername :one
SELECT *
FROM users
WHERE username = $1;

-- name: GetUserByID :one
SELECT *
FROM users
WHERE id = $1;

-- name: MarkUserEmailVerified :exec
UPDATE users
SET email_verified_at = NOW()
WHERE id = $1;

-- name: UpdateUserLastLogin :exec
UPDATE users
SET last_login_at = NOW(),
    last_seen_at = NOW(),
    failed_login_count = 0,
    locked_until = NULL
WHERE id = $1;

-- name: TouchUserSeen :exec
UPDATE users
SET last_seen_at = NOW()
WHERE id = $1;

-- name: IncrementFailedLogin :exec
UPDATE users
SET failed_login_count = failed_login_count + 1
WHERE id = $1;

-- name: LockUserUntil :exec
UPDATE users
SET locked_until = $2,
    disabled_reason = $3
WHERE id = $1;

-- name: RestoreUserAccess :exec
UPDATE users
SET is_active = TRUE,
    email_verified_at = COALESCE(email_verified_at, NOW()),
    failed_login_count = 0,
    locked_until = NULL,
    disabled_reason = NULL,
    disabled_at = NULL
WHERE id = $1;

-- name: DisableInactiveUsers :many
UPDATE users
SET is_active = FALSE,
    disabled_reason = 'inactivity',
    disabled_at = NOW()
WHERE is_active = TRUE
  AND COALESCE(last_login_at, created_at) < $1
RETURNING *;