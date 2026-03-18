-- name: GetOAuthAccountByProviderIdentity :one
SELECT *
FROM oauth_accounts
WHERE provider = $1
  AND provider_user_id = $2;

-- name: GetOAuthAccountByUserIDAndProvider :one
SELECT *
FROM oauth_accounts
WHERE user_id = $1
  AND provider = $2;

-- name: UpsertOAuthAccount :one
INSERT INTO oauth_accounts (
    user_id,
    provider,
    provider_user_id,
    access_token_ciphertext,
    refresh_token_ciphertext,
    token_expires_at
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
)
ON CONFLICT (provider, provider_user_id)
DO UPDATE SET
    user_id = EXCLUDED.user_id,
    access_token_ciphertext = EXCLUDED.access_token_ciphertext,
    refresh_token_ciphertext = EXCLUDED.refresh_token_ciphertext,
    token_expires_at = EXCLUDED.token_expires_at
RETURNING *;