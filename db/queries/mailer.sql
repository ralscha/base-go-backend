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
    last_error = $2,
    available_at = NOW() + ($3 * INTERVAL '1 second')
WHERE id = $1;