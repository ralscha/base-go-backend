-- name: AddUserRole :exec
INSERT INTO user_roles (
    user_id,
    role_id
) VALUES (
    $1,
    $2
)
ON CONFLICT DO NOTHING;

-- name: GetRoleByName :one
SELECT *
FROM roles
WHERE name = $1;

-- name: ListUserRoleNames :many
SELECT roles.name
FROM roles
JOIN user_roles ON user_roles.role_id = roles.id
WHERE user_roles.user_id = $1
ORDER BY roles.name;