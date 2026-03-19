package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"base/internal/config"
)

func TestApplyOAuthProviderDefaults(t *testing.T) {
	provider := applyOAuthProviderDefaults(config.OAuthProviderConfig{})

	if !reflect.DeepEqual(provider.Scopes, []string{"openid", "email", "profile"}) {
		t.Fatalf("Scopes = %v, want default scopes", provider.Scopes)
	}
	if provider.SubjectField != "sub" || provider.EmailField != "email" || provider.EmailVerifiedField != "email_verified" || provider.UsernameField != "preferred_username" || provider.NameField != "name" {
		t.Fatalf("unexpected default fields: %+v", provider)
	}
}

func TestNewOAuthProviderClientsSkipsDisabledAndNormalizesNames(t *testing.T) {
	clients, err := newOAuthProviderClients(config.OAuthConfig{
		Providers: map[string]config.OAuthProviderConfig{
			" GitHub ": {
				Enabled:      true,
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				AuthURL:      "https://example.com/auth",
				TokenURL:     "https://example.com/token",
				UserInfoURL:  "https://example.com/userinfo",
				RedirectURL:  "https://app.example.com/callback",
			},
			"google": {Enabled: false},
		},
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("newOAuthProviderClients() error = %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("len(clients) = %d, want 1", len(clients))
	}

	client, ok := clients["github"].(configuredOAuthProvider)
	if !ok {
		t.Fatalf("clients[github] type = %T, want configuredOAuthProvider", clients["github"])
	}
	if client.name != "github" {
		t.Fatalf("provider name = %q, want github", client.name)
	}
	if !reflect.DeepEqual(client.config.Scopes, []string{"openid", "email", "profile"}) {
		t.Fatalf("provider scopes = %v, want defaults", client.config.Scopes)
	}
}

func TestConfiguredOAuthProviderAuthorizationURL(t *testing.T) {
	provider := configuredOAuthProvider{
		config: config.OAuthProviderConfig{
			AuthURL:     "https://example.com/oauth/authorize",
			ClientID:    "client-id",
			RedirectURL: "https://app.example.com/callback",
			Scopes:      []string{"openid", "email"},
		},
	}

	rawURL := provider.AuthorizationURL("state-123", "challenge-456")
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("AuthorizationURL() produced invalid URL: %v", err)
	}

	query := parsedURL.Query()
	if query.Get("response_type") != "code" {
		t.Fatalf("response_type = %q, want code", query.Get("response_type"))
	}
	if query.Get("client_id") != "client-id" {
		t.Fatalf("client_id = %q, want client-id", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Fatalf("redirect_uri = %q, want callback URL", query.Get("redirect_uri"))
	}
	if query.Get("scope") != "openid email" {
		t.Fatalf("scope = %q, want openid email", query.Get("scope"))
	}
	if query.Get("state") != "state-123" {
		t.Fatalf("state = %q, want state-123", query.Get("state"))
	}
	if query.Get("code_challenge") != "challenge-456" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected PKCE query params: %v", query)
	}
}

func TestDecodeOAuthFlow(t *testing.T) {
	state := oauthFlowState{
		Provider:     "github",
		State:        "state-token",
		CodeVerifier: "verifier-token",
		StartedAt:    time.Unix(1700000000, 0).UTC(),
		LinkUserID:   42,
	}

	encoded, err := encodeOAuthFlow(state)
	if err != nil {
		t.Fatalf("encodeOAuthFlow() error = %v", err)
	}

	decoded, err := decodeOAuthFlow(encoded)
	if err != nil {
		t.Fatalf("decodeOAuthFlow() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, state) {
		t.Fatalf("decodeOAuthFlow() = %+v, want %+v", decoded, state)
	}

	if _, err := decodeOAuthFlow([]byte(" ")); !errors.Is(err, ErrOAuthState) {
		t.Fatalf("decodeOAuthFlow(blank) error = %v, want %v", err, ErrOAuthState)
	}
	if _, err := decodeOAuthFlow([]byte("not-json")); !errors.Is(err, ErrOAuthState) {
		t.Fatalf("decodeOAuthFlow(invalid) error = %v, want %v", err, ErrOAuthState)
	}
}

func TestPayloadHelpersAndUtilityFunctions(t *testing.T) {
	payload := map[string]any{
		"email":            "  USER@example.com  ",
		"email_verified":   "TRUE",
		"display_name":     123,
		"whitespace_value": "  hello  ",
	}

	if got := payloadString(payload, "email"); got != "USER@example.com" {
		t.Fatalf("payloadString(email) = %q, want trimmed string", got)
	}
	if got := payloadString(payload, "display_name"); got != "123" {
		t.Fatalf("payloadString(display_name) = %q, want 123", got)
	}
	if got := payloadString(payload, "missing"); got != "" {
		t.Fatalf("payloadString(missing) = %q, want empty", got)
	}

	if got := payloadBool(payload, "email_verified", false); !got {
		t.Fatal("payloadBool(email_verified) = false, want true")
	}
	if got := payloadBool(payload, "missing", true); !got {
		t.Fatal("payloadBool(missing) = false, want default true")
	}
	if got := payloadBool(payload, "", false); got {
		t.Fatal("payloadBool(blank field) = true, want default false")
	}

	if got := sanitizeUsername("  Jane Doe!@# "); got != "janedoe" {
		t.Fatalf("sanitizeUsername() = %q, want janedoe", got)
	}
	if got := modeForUserID(7); got != "link" {
		t.Fatalf("modeForUserID(7) = %q, want link", got)
	}
	if got := modeForUserID(0); got != "login" {
		t.Fatalf("modeForUserID(0) = %q, want login", got)
	}

	challenge := pkceCodeChallenge("verifier-value")
	if challenge == "" || strings.Contains(challenge, "=") {
		t.Fatalf("pkceCodeChallenge() = %q, want non-empty base64url string", challenge)
	}
	if challenge != pkceCodeChallenge("verifier-value") {
		t.Fatal("pkceCodeChallenge() should be deterministic for the same verifier")
	}

	tokenOne, err := randomToken(4)
	if err != nil {
		t.Fatalf("randomToken() error = %v", err)
	}
	tokenTwo, err := randomToken(4)
	if err != nil {
		t.Fatalf("randomToken() second call error = %v", err)
	}
	if len(tokenOne) != 6 {
		t.Fatalf("len(randomToken(4)) = %d, want 6", len(tokenOne))
	}
	if tokenOne == tokenTwo {
		t.Fatal("randomToken() returned identical tokens on consecutive calls")
	}

	sealed, err := sealStoredSecret("top-secret", strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("sealStoredSecret() error = %v", err)
	}
	aead, err := newGCM(strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("newGCM() error = %v", err)
	}
	plaintext, err := decryptSecret(sealed[aead.NonceSize():], sealed[:aead.NonceSize()], strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("decryptSecret(sealed) error = %v", err)
	}
	if plaintext != "top-secret" {
		t.Fatalf("decryptSecret(sealed) = %q, want top-secret", plaintext)
	}

	blankSealed, err := sealStoredSecret("   ", strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("sealStoredSecret(blank) error = %v", err)
	}
	if blankSealed != nil {
		t.Fatalf("sealStoredSecret(blank) = %v, want nil", blankSealed)
	}

	if !subtleCompare("match", "match") {
		t.Fatal("subtleCompare() = false, want true for equal strings")
	}
	if subtleCompare("match", "different") {
		t.Fatal("subtleCompare() = true, want false for different strings")
	}

	if !errorsIsNoRows(sql.ErrNoRows) {
		t.Fatal("errorsIsNoRows(sql.ErrNoRows) = false, want true")
	}
	if errorsIsNoRows(errors.New("no rows")) {
		t.Fatal("errorsIsNoRows(custom error) = true, want false")
	}

	nonZeroTime := time.Date(2026, time.March, 19, 8, 30, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	nullTimestamp := nullTime(nonZeroTime)
	if !nullTimestamp.Valid {
		t.Fatal("nullTime(non-zero) returned invalid timestamp")
	}
	if nullTimestamp.Time.Location() != time.UTC {
		t.Fatalf("nullTime(non-zero) location = %v, want UTC", nullTimestamp.Time.Location())
	}
	if zeroTimestamp := nullTime(time.Time{}); zeroTimestamp.Valid {
		t.Fatal("nullTime(zero) returned valid timestamp")
	}

	generated := generateOAuthUsername("github", OAuthProfile{Username: " Jane Doe "})
	if !strings.HasPrefix(generated, "janedoe-") {
		t.Fatalf("generateOAuthUsername(username) = %q, want janedoe-*", generated)
	}

	fallbackToName := generateOAuthUsername("github", OAuthProfile{Name: "Jane Doe"})
	if !strings.HasPrefix(fallbackToName, "janedoe-") {
		t.Fatalf("generateOAuthUsername(name) = %q, want janedoe-*", fallbackToName)
	}

	fallbackToEmail := generateOAuthUsername("github", OAuthProfile{Email: "jane@example.com"})
	if !strings.HasPrefix(fallbackToEmail, "jane-") {
		t.Fatalf("generateOAuthUsername(email) = %q, want jane-*", fallbackToEmail)
	}

	fallbackToProvider := generateOAuthUsername("github", OAuthProfile{})
	if !strings.HasPrefix(fallbackToProvider, "github-") {
		t.Fatalf("generateOAuthUsername(provider) = %q, want github-*", fallbackToProvider)
	}
}
