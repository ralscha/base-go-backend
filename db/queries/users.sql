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

-- name: GetUserWithPasswordByEmail :one
SELECT *
FROM users
WHERE email = $1
  AND password_hash IS NOT NULL;

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
    last_failed_login_at = NULL,
    locked_until = NULL,
    disabled_reason = CASE
        WHEN disabled_reason = 'failed_login_attempts' THEN NULL
        ELSE disabled_reason
    END
WHERE id = $1;

-- name: TouchUserSeen :exec
UPDATE users
SET last_seen_at = NOW()
WHERE id = $1;

-- name: IncrementUserAuthVersion :one
UPDATE users
SET auth_version = auth_version + 1
WHERE id = $1
RETURNING auth_version;

-- name: RecordFailedLogin :one
UPDATE users
SET failed_login_count = CASE
		WHEN last_failed_login_at IS NULL
		  OR last_failed_login_at < NOW() - (sqlc.arg(window_seconds)::bigint * INTERVAL '1 second')
        THEN 1
        ELSE failed_login_count + 1
    END,
    last_failed_login_at = NOW()
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: ResetLoginFailures :exec
UPDATE users
SET failed_login_count = 0,
    last_failed_login_at = NULL,
    locked_until = NULL,
    disabled_reason = CASE
        WHEN disabled_reason = 'failed_login_attempts' THEN NULL
        ELSE disabled_reason
    END
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
    last_failed_login_at = NULL,
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
