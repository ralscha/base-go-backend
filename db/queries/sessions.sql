-- name: CreateUserSessionRecord :exec
INSERT INTO user_sessions (
    token,
    user_id,
    device_id,
    expiry
) VALUES (
    $1,
    $2,
    $3,
    $4
);

-- name: RevokeDeviceSessions :exec
UPDATE user_sessions
SET revoked_at = NOW()
WHERE user_id = $1
  AND device_id = $2
  AND revoked_at IS NULL;

-- name: DeleteExpiredUserSessions :execrows
DELETE FROM user_sessions
WHERE expiry < NOW()
   OR revoked_at IS NOT NULL;

-- name: RevokeAllUserSessions :exec
DELETE FROM sessions
WHERE token IN (
    SELECT token FROM user_sessions
    WHERE user_id = $1
      AND revoked_at IS NULL
);

-- name: RevokeAllUserSessionRecords :exec
UPDATE user_sessions
SET revoked_at = NOW()
WHERE user_id = $1
  AND revoked_at IS NULL;
