# base - Go Backend Template

A production-ready Go backend template with authentication, authorization, OAuth2, WebAuthn (passkeys), TOTP, email verification, and background job processing.

## Features

- **Authentication**: Password-based login with Argon2id hashing, email verification, password reset, and account recovery
- **Two-Factor Authentication**: TOTP (Time-based One-Time Password) support
- **Passkeys (WebAuthn)**: Passwordless authentication with discoverable credentials
- **OAuth2/OIDC**: Pluggable OAuth providers with PKCE flow
- **Role-Based Access Control**: Admin and user roles with pluggable permission middleware
- **Session Management**: PostgreSQL-backed sessions with configurable lifetimes
- **Email Outbox**: Asynchronous email delivery with retry and failure tracking
- **Rate Limiting**: Login rate limiting with PostgreSQL-backed token buckets
- **Background Jobs**: River-based job processing (email delivery, cleanup, inactivity checks)
- **Database Migrations**: Goose-based schema migrations with embedded SQL files
- **Configuration**: YAML config with environment variable overrides (via Koanf)
- **Structured Logging**: JSON logging via `log/slog`
- **Test Infrastructure**: Testcontainers-based PostgreSQL for integration tests

## Quick Start

### Prerequisites

- Go 1.26+
- Docker (for PostgreSQL, Inbucket, sqlc codegen, and tests)
- [Task](https://taskfile.dev/) (optional, for convenience commands)

### Development Setup

```bash
# Start PostgreSQL and Inbucket (mail catcher)
docker compose up -d

# Run database migrations and start the server
go run ./cmd/app

# Or use Task
task run
```

The API is available at `http://localhost:8080`.

### Running Tests

```bash
# Run all tests (requires Docker for Testcontainers)
task test

# Generate coverage report
task coverage

# Run linter
task lint
```

## Project Structure

```
.
|-- cmd/
|   |-- app/                # Application entry point
|   `-- coveragefilter/     # Coverage report filter utility
|-- config/
|   `-- config.yaml         # Default configuration
|-- db/
|   |-- migrations/         # Goose SQL migrations (embedded)
|   `-- queries/            # sqlc query definitions
|-- internal/
|   |-- app/                # Application bootstrap and lifecycle
|   |-- auth/               # Authentication and authorization logic
|   |-- cache/              # Generic in-memory cache with TTL
|   |-- config/             # Configuration loading and validation
|   |-- database/           # Database connection and migration runner
|   |-- httpapi/            # HTTP API layer
|   |   |-- handlers/       # Request handlers
|   |   |-- jsonio/         # JSON request/response helpers
|   |   `-- middleware/     # HTTP middleware
|   |-- mailer/             # SMTP mailer
|   |-- river/              # River background job client and workers
|   |   `-- jobs/           # Job implementations
|   |-- store/
|   |   |-- dbtype/         # Custom database types (JSONB)
|   |   `-- sqlc/           # Generated sqlc code
|   |-- testutil/           # Test helpers (Testcontainers PostgreSQL)
|   `-- validation/         # Request validation framework
|-- sqlc/                   # sqlc Docker build files
|-- docker-compose.yml      # Development services
|-- Taskfile.yml            # Task runner commands
`-- GOING_PROD.md           # Production deployment checklist
```

## Configuration

Configuration is loaded from `config/config.yaml` and overridden by environment variables prefixed with `BASE_`. Environment variable names join config path segments with `_` while preserving snake_case field names, so `BASE_DATABASE_MAX_OPEN_CONNS` overrides `database.max_open_conns` and `BASE_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID` overrides `oauth.providers.google.client_id`. String slices accept comma-separated values such as `BASE_SECURITY_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com`.

| Config Key | Env Var | Description |
|---|---|---|
| `app.env` | `BASE_APP_ENV` | Environment: `development`, `test`, or `production` |
| `app.log_level` | `BASE_APP_LOG_LEVEL` | Log level: `debug`, `info`, `warn`, `error` |
| `http.address` | `BASE_HTTP_ADDRESS` | Listen address (e.g., `:8080`, `127.0.0.1:8080`) |
| `http.trusted_proxies` | `BASE_HTTP_TRUSTED_PROXIES` | Trusted proxy IPs/CIDRs for `X-Forwarded-For` and `X-Real-IP` handling (comma-separated) |
| `database.url` | `BASE_DATABASE_URL` | PostgreSQL connection string |
| `database.max_open_conns` | `BASE_DATABASE_MAX_OPEN_CONNS` | Maximum open database connections |
| `session.secure` | `BASE_SESSION_SECURE` | Set to `true` in production (HTTPS) |
| `security.allowed_origins` | `BASE_SECURITY_ALLOWED_ORIGINS` | Allowed CORS origins for browser clients (comma-separated) |
| `security.encryption_key` | `BASE_SECURITY_ENCRYPTION_KEY` | 32+ char secret for DB encryption |
| `river.enabled` | `BASE_RIVER_ENABLED` | Enable background job processing |
| `mailer.enabled` | `BASE_MAILER_ENABLED` | Enable email sending |

See `config/config.yaml` for all options. See [GOING_PROD.md](GOING_PROD.md) for production configuration guidance.

## API Endpoints

### Public
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Register a new user |
| `POST` | `/api/v1/auth/login` | Login with email/password (+ optional TOTP) |
| `GET` | `/api/v1/auth/verify-email` | Verify email with token |
| `POST` | `/api/v1/auth/password-reset/request` | Request password reset email |
| `POST` | `/api/v1/auth/password-reset/confirm` | Confirm password reset |
| `POST` | `/api/v1/auth/account-recovery/request` | Request account recovery |
| `POST` | `/api/v1/auth/account-recovery/confirm` | Confirm account recovery |
| `GET` | `/api/v1/auth/oauth/{provider}/start` | Start OAuth flow |
| `GET` | `/api/v1/auth/oauth/{provider}/callback` | OAuth callback |
| `POST` | `/api/v1/auth/passkeys/login/start` | Begin passkey login |
| `POST` | `/api/v1/auth/passkeys/login/finish` | Complete passkey login |

### Authenticated
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/auth/logout` | Destroy session |
| `GET` | `/api/v1/auth/me` | Get current user |
| `POST` | `/api/v1/auth/passkeys/register/start` | Begin passkey registration |
| `POST` | `/api/v1/auth/passkeys/register/finish` | Complete passkey registration |
| `POST` | `/api/v1/auth/totp/setup` | Generate TOTP secret |
| `POST` | `/api/v1/auth/totp/enable` | Enable TOTP |
| `POST` | `/api/v1/auth/totp/disable` | Disable TOTP |

### Admin
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/admin/access` | Admin-only endpoint |

### Health
| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `GET` | `/readiness` | Readiness check (includes DB ping) |

## Libraries

### Core Dependencies

| Library | Version | Purpose |
|---|---|---|
| [github.com/go-chi/chi/v5](https://github.com/go-chi/chi) | v5.3.0 | HTTP router with middleware support |
| [github.com/jackc/pgx/v5](https://github.com/jackc/pgx) | v5.10.0 | PostgreSQL driver and connection pool |
| [github.com/alexedwards/scs/v2](https://github.com/alexedwards/scs) | v2.9.0 | HTTP session management |
| [github.com/alexedwards/scs/pgxstore](https://github.com/alexedwards/scs) | v0.0.0-20251002162104-209de6e426de | PostgreSQL session store for SCS |
| [github.com/knadh/koanf/v2](https://github.com/knadh/koanf) | v2.3.5 | Configuration management (YAML + env) |

### Authentication & Security

| Library | Version | Purpose |
|---|---|---|
| [github.com/alexedwards/argon2id](https://github.com/alexedwards/argon2id) | v1.0.0 | Argon2id password hashing |
| [github.com/pquerna/otp](https://github.com/pquerna/otp) | v1.5.0 | TOTP (two-factor) generation and validation |
| [github.com/go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) | v0.17.4 | WebAuthn / Passkey authentication |
| [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt) | v5.3.1 | JWT parsing (indirect, via WebAuthn) |
| [github.com/google/uuid](https://github.com/google/uuid) | v1.6.0 | UUID generation (passkey AAGUID) |

### Background Jobs & Messaging

| Library | Version | Purpose |
|---|---|---|
| [github.com/riverqueue/river](https://github.com/riverqueue/river) | v0.39.0 | PostgreSQL-backed job queue (email outbox, cleanup, inactivity checks) |

### Database & Migrations

| Library | Version | Purpose |
|---|---|---|
| [github.com/pressly/goose/v3](https://github.com/pressly/goose) | v3.27.1 | Database schema migrations |
| [github.com/lib/pq](https://github.com/lib/pq) | v1.12.3 | PostgreSQL driver (used by test utilities) |

### Rate Limiting

| Library | Version | Purpose |
|---|---|---|
| [github.com/ralscha/ratelimiter-pg](https://github.com/ralscha/ratelimiter-pg) | v0.0.0-20260531135312-9a7504910818 | PostgreSQL-backed token bucket rate limiter |

### Testing

| Library | Version | Purpose |
|---|---|---|
| [github.com/testcontainers/testcontainers-go](https://github.com/testcontainers/testcontainers-go) | v0.42.0 | Docker-based integration testing with real PostgreSQL |
| [github.com/stretchr/testify](https://github.com/stretchr/testify) | v1.11.1 | Test assertions (indirect) |

### Development Tools

| Tool | Purpose |
|---|---|
| [sqlc](https://sqlc.dev/) (v1.30.0) | Type-safe SQL code generation (run via Docker) |
| [golangci-lint](https://golangci-lint.run/) (v2.12.2) | Go linter (run via Docker) |
| [Docker Compose](https://docs.docker.com/compose/) | Local PostgreSQL + Inbucket for development |
| [Task](https://taskfile.dev/) | Build/test automation |

## Code Generation

SQL queries are defined in `db/queries/` and Go code is generated with [sqlc](https://sqlc.dev/):

```bash
task db:build-sqlc    # Build the sqlc Docker image
task db:run-sqlc      # Generate Go code from SQL queries
```

## Architecture Notes

- **Dual DB handles**: The app maintains both a `database/sql` handle (`*sql.DB`) and a `pgxpool` handle (`*pgxpool.Pool`). The `sql.DB` is used for sqlc-generated queries and migrations; `pgxpool` is used by River, SCS sessions, and the rate limiter.
- **River outbox safety**: The periodic email outbox job is inserted uniquely so only one outbox sweep can be queued or running at a time, which avoids overlapping email sends.
- **Proxy trust boundary**: Forwarded client IP headers are only honored when the immediate peer matches `http.trusted_proxies`. Leave that list empty unless the app is behind a proxy you control.
- **Encryption at rest**: TOTP secrets and OAuth tokens stored in the database are encrypted with AES-256-GCM using the configured `security.encryption_key`.
- **Credential masking**: Login failures intentionally return a generic "Invalid email or password" message regardless of whether the email exists, the account is locked, disabled, or unverified.
- **Test isolation**: Each test gets its own PostgreSQL database created from a shared Testcontainers container, ensuring full isolation without per-test container overhead.

## License

MIT
