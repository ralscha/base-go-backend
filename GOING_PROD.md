# Going To Production

This document is the production checklist for this service.

The app itself serves plain HTTP. In production, put it behind Caddy for TLS and public ingress.

## 1. Pick Your Public Hostnames

Decide which hostname will serve the app, for example:

- `api.example.com` for the API
- `app.example.com` for the frontend, if it is separate

If you are using OAuth, WebAuthn, cookies, and email links, these hostnames need to be finalized before you configure providers.

## 2. Set Up DNS

Create DNS records for the machine that will run Caddy.

- Add an `A` record for IPv4, for example `api.example.com -> 203.0.113.10`
- Add an `AAAA` record for IPv6, for example `api.example.com -> 2001:db8::10`

If you only have IPv4, the `A` record is enough.

Validate DNS before continuing:

```powershell
Resolve-DnsName api.example.com
```

You want the hostname to resolve to the public IP of the server that will terminate TLS.

## 3. Open Network Ports

The public server needs inbound access for:

- `80/tcp` for ACME HTTP challenge and HTTP to HTTPS redirect
- `443/tcp` for HTTPS traffic

Do not expose the Go service directly on the internet. Expose only Caddy.

## 4. Run The App On A Private HTTP Listener

This app should listen on a local interface behind Caddy.

Recommended production bind address:

```yaml
http:
  address: "127.0.0.1:8080"
```

That keeps the Go process private while Caddy accepts the public traffic.

## 5. Production Config Changes

The default [config/config.yaml](config/config.yaml) is a development config. Do not use it unchanged in production.

You can supply production settings through the YAML file, `BASE_` environment variables, or a mix of both. Environment variable names join config path segments with `_` while preserving snake_case field names, so `BASE_DATABASE_URL`, `BASE_DATABASE_MAX_OPEN_CONNS`, and `BASE_SECURITY_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com` all map cleanly to their config keys.

At minimum, review and change these sections.

### App

```yaml
app:
  env: production
  log_level: info
```

- Set `env: production`
- Reduce log verbosity unless you intentionally want debug logs in production

### HTTP

```yaml
http:
  address: "127.0.0.1:8080"
  read_timeout: 15s
  read_header_timeout: 10s
  write_timeout: 30s
  idle_timeout: 60s
  shutdown_timeout: 20s
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
```

- Keep the app on a private bind address
- Set `trusted_proxies` to the IPs or CIDRs of the reverse proxies that are allowed to supply `X-Forwarded-For` and `X-Real-IP`
- If Caddy runs on the same host and connects over loopback, trust only loopback as shown above
- Timeouts can stay as they are unless you have large uploads or long-lived requests

### Database

Use a real production Postgres instance, not the local dev connection string.

Example:

```yaml
database:
  url: postgres://base_user:REDACTED@db.example.com:5432/base?sslmode=require
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m
  conn_max_idle_time: 2m
```

- Use `sslmode=require` or stricter
- Use separate production credentials
- Make sure the DB firewall only allows the app host

### Session Cookies

For production behind HTTPS:

```yaml
session:
  cookie_name: base_session
  lifetime: 24h
  idle_timeout: 12h
  same_site: lax
  secure: true
  http_only: true
  persist: true
```

- `secure: true` is required for HTTPS-only cookies
- `http_only: true` should remain enabled
- `same_site: lax` is generally fine for a normal web app and works with top-level OAuth redirects

### Security

This is the most important section to review.

```yaml
security:
  allowed_origins:
    - https://app.example.com
  encryption_key: CHANGE_ME_TO_A_LONG_RANDOM_SECRET
  password_reset_ttl: 1h
  email_verification_ttl: 24h
  recovery_ttl: 30m
  failed_login_threshold: 5
  failed_login_window: 15m
  inactivity_disable_after: 8760h
  totp_issuer: example.com
```

- Replace `encryption_key` with a strong random value of at least 32 characters
- Do not reuse the default key from development
- Set `allowed_origins` to your actual frontend origin if the frontend is hosted separately
- Set `totp_issuer` to your production brand or domain so authenticator apps show the right issuer name

The `security.encryption_key` is used for application-level encryption of secrets stored in the database. In this codebase that includes TOTP shared secrets and OAuth provider tokens. If you change this key later without a rotation plan, previously stored encrypted values will no longer decrypt correctly.

Important: the app refuses to start in non-development environments if the default encryption key is still present. That check is implemented in [internal/config/config.go](internal/config/config.go).

### WebAuthn

If you use passkeys, these values must match your production hostname.

Example:

```yaml
webauthn:
  rp_id: api.example.com
  rp_display_name: Example
  rp_origins:
    - https://app.example.com
    - https://api.example.com
```

- `rp_id` must be a real domain you control
- `rp_origins` must contain the actual HTTPS origins used by the browser

### Mailer

If you want email verification, password reset, and account recovery to work in production, configure SMTP.

Example:

```yaml
mailer:
  enabled: true
  from: no-reply@example.com
  host: smtp.example.com
  port: 587
  username: smtp-user
  password: REDACTED
  require_tls: true
```

### River (Background Jobs)

River handles email outbox processing, periodic cleanup, and inactivity checks.

```yaml
river:
  enabled: true
  email_outbox_every: 1m
  email_outbox_retention: 720h
  cleanup_every: 1h
  inactivity_check_every: 24h
  max_workers: 100
```

- `email_outbox_retention` controls how long sent/failed emails are kept before deletion
- `max_workers` must stay between `1` and `10000`; tune it based on your workload and process count
- River interval values must stay greater than zero
- The periodic email outbox job is inserted uniquely so only one outbox sweep can be queued or running at a time
- River manages its own schema migrations automatically via `rivermigrate`

Leave this enabled unless you move those jobs to a separate worker process.

## 6. Set Up Caddy As Reverse Proxy With TLS

Caddy is a good fit here because it will automatically provision and renew TLS certificates.

Example `Caddyfile`:

```caddy
api.example.com {
    encode zstd gzip

    reverse_proxy 127.0.0.1:8080

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
    }
}
```

Notes:

- Caddy listens publicly on `:80` and `:443`
- Caddy fetches certificates automatically once DNS points at the box
- The Go app continues to listen only on `127.0.0.1:8080`
- If you split frontend and API across different domains, create separate site blocks
  - In this production setup, Caddy is the single owner of these response security headers, so the Go app does not need to emit them itself

If you run the API on the same host as another web app, keep the hostname-specific Caddy blocks separate and explicit.

## 7. Start The App As A Service

Use a service manager such as `systemd` on Linux so the app restarts automatically and has controlled environment/config.

Typical production pattern:

- Deploy the compiled Go binary
- Store the production config file on disk with restricted permissions
- Run the app as a non-root user
- Keep Caddy as the only public-facing process

This app starts from [cmd/app/main.go](cmd/app/main.go), loads config, opens Postgres, runs migrations, starts the scheduler, and serves HTTP.

## 8. Run Database Migrations Safely

The app currently runs migrations on startup from [internal/app/app.go](internal/app/app.go).

That is convenient, but in production you should still treat schema changes carefully:

- back up the database before risky migrations
- review migration SQL before deploy
- test migrations against a staging environment first
- avoid multiple simultaneous first-start deploys if you later scale horizontally

## 9. Production OAuth Setup

OAuth does not work in production until you register the app with each provider.

The app already supports the OAuth flow and exposes these routes:

- `/api/v1/auth/oauth/{provider}/start`
- `/api/v1/auth/oauth/{provider}/callback`

The provider config lives in [config/config.yaml](config/config.yaml) and the types are defined in [internal/config/config.go](internal/config/config.go).

### What You Must Do With The Provider

For each provider such as Google, GitHub, or Microsoft:

1. Create an OAuth application in the provider's developer console.
2. Set the authorized redirect URI to your production callback URL.
3. Copy the issued client ID and client secret into this app's config.
4. Enable the provider in the config.

For Google, a typical production redirect URI would be:

```text
https://api.example.com/api/v1/auth/oauth/google/callback
```

That value must match exactly in both places:

- the provider console
- `oauth.providers.google.redirect_url`

### Example Google Production Config

```yaml
oauth:
  state_ttl: 10m
  state_bytes: 32
  pkce_verifier_bytes: 32
  providers:
    google:
      enabled: true
      client_id: YOUR_GOOGLE_CLIENT_ID
      client_secret: YOUR_GOOGLE_CLIENT_SECRET
      auth_url: https://accounts.google.com/o/oauth2/v2/auth
      token_url: https://oauth2.googleapis.com/token
      user_info_url: https://openidconnect.googleapis.com/v1/userinfo
      redirect_url: https://api.example.com/api/v1/auth/oauth/google/callback
      scopes:
        - openid
        - email
        - profile
      subject_field: sub
      email_field: email
      email_verified_field: email_verified
      username_field: preferred_username
      name_field: name
```

### OAuth Production Notes

- Keep the callback URL on HTTPS only
- Do not reuse localhost redirect URLs in production
- If the frontend initiates login, the frontend should call the app's `/start` endpoint and then redirect the browser to the returned authorization URL
- The app stores OAuth provider tokens encrypted using `security.encryption_key`, so protecting that key matters

## 10. Smoke Test Before Real Traffic

Before opening the service to users, validate the full flow.

Checklist:

1. Open `https://api.example.com/health`
2. Confirm Caddy serves a valid certificate
3. Confirm the app can reach Postgres
4. Register a user
5. Verify email delivery works
6. Log in with password
7. Test OAuth login with the real production hostname
8. If enabled, test passkeys after updating WebAuthn settings
9. Test password reset and account recovery emails

## 11. Common Production Mistakes

Avoid these:

- leaving `security.encryption_key` at the development default
- leaving `session.secure: false`
- pointing DNS at the app directly instead of at Caddy
- forgetting to open `80` and `443`
- registering the wrong OAuth redirect URL with the provider
- leaving WebAuthn origins on localhost
- using a non-TLS SMTP setup for production mail
- exposing Postgres directly to the public internet

## 12. Minimal Production Checklist

1. Create the server and public IP.
2. Add `A` and optionally `AAAA` DNS records.
3. Install Caddy and configure a reverse proxy for your hostname.
4. Run the Go app on `127.0.0.1:8080`.
5. Replace the default encryption key.
6. Turn on secure cookies and secure CSRF behavior.
7. Point the app at production Postgres with TLS.
8. Configure SMTP.
9. Update WebAuthn production domain settings if using passkeys.
10. Register the app with each OAuth provider and set exact callback URLs.
11. Smoke test login, email, OAuth, and recovery flows.
