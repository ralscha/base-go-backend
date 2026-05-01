-- name: EnqueueEmail :one
INSERT INTO email_outbox (
    template,
    recipient,
    subject,
    payload,
    available_at
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
RETURNING *;

-- name: ListPendingEmails :many
SELECT *
FROM email_outbox
WHERE sent_at IS NULL
  AND available_at <= NOW()
ORDER BY available_at ASC
LIMIT $1;

-- name: MarkEmailSent :exec
UPDATE email_outbox
SET sent_at = NOW()
WHERE id = $1;

-- name: MarkEmailFailed :exec
UPDATE email_outbox
SET attempts = attempts + 1,
    last_error = sqlc.arg(last_error),
    available_at = NOW() + (sqlc.arg(retry_delay_seconds)::int * INTERVAL '1 second')
WHERE id = sqlc.arg(id);

-- name: DeleteSentEmailsBefore :execrows
DELETE FROM email_outbox
WHERE sent_at IS NOT NULL
  AND sent_at < $1;

-- name: DeleteFailedEmailsBefore :execrows
DELETE FROM email_outbox
WHERE sent_at IS NULL
  AND last_error IS NOT NULL
  AND available_at < $1;