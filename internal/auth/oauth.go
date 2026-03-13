package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"base/internal/config"
	"base/internal/store/sqlc"
)

type OAuthAuthenticationResult struct {
	Principal SessionPrincipal `json:"user"`
	Provider  string           `json:"provider"`
	Mode      string           `json:"mode"`
	Created   bool             `json:"created"`
	Linked    bool             `json:"linked"`
}

type OAuthProviderClient interface {
	AuthorizationURL(state string, codeChallenge string) string
	ExchangeCode(ctx context.Context, code string, codeVerifier string) (OAuthTokens, error)
	FetchProfile(ctx context.Context, accessToken string) (OAuthProfile, error)
}

type OAuthTokens struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

type OAuthProfile struct {
	Subject       string
	Email         string
	EmailVerified bool
	Username      string
	Name          string
}

type oauthFlowState struct {
	Provider     string    `json:"provider"`
	State        string    `json:"state"`
	CodeVerifier string    `json:"code_verifier"`
	StartedAt    time.Time `json:"started_at"`
	LinkUserID   int64     `json:"link_user_id,omitempty"`
}

type configuredOAuthProvider struct {
	name       string
	config     config.OAuthProviderConfig
	httpClient *http.Client
}

func newOAuthProviderClients(cfg config.OAuthConfig, httpClient *http.Client) (map[string]OAuthProviderClient, error) {
	providers := make(map[string]OAuthProviderClient, len(cfg.Providers))
	for name, providerCfg := range cfg.Providers {
		if !providerCfg.Enabled {
			continue
		}
		normalizedName := strings.ToLower(strings.TrimSpace(name))
		providers[normalizedName] = configuredOAuthProvider{
			name:       normalizedName,
			config:     applyOAuthProviderDefaults(providerCfg),
			httpClient: httpClient,
		}
	}
	return providers, nil
}

func (provider configuredOAuthProvider) AuthorizationURL(state string, codeChallenge string) string {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", provider.config.ClientID)
	values.Set("redirect_uri", provider.config.RedirectURL)
	values.Set("scope", strings.Join(provider.config.Scopes, " "))
	values.Set("state", state)
	values.Set("code_challenge", codeChallenge)
	values.Set("code_challenge_method", "S256")

	parsedURL, err := url.Parse(provider.config.AuthURL)
	if err != nil {
		return provider.config.AuthURL
	}
	parsedURL.RawQuery = values.Encode()
	return parsedURL.String()
}

func (provider configuredOAuthProvider) ExchangeCode(ctx context.Context, code string, codeVerifier string) (OAuthTokens, error) {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("client_id", provider.config.ClientID)
	values.Set("client_secret", provider.config.ClientSecret)
	values.Set("redirect_uri", provider.config.RedirectURL)
	values.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.config.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return OAuthTokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := provider.httpClient.Do(req)
	if err != nil {
		return OAuthTokens{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return OAuthTokens{}, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return OAuthTokens{}, err
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return OAuthTokens{}, ErrRequestFailed
	}

	tokens := OAuthTokens{
		AccessToken:  strings.TrimSpace(payload.AccessToken),
		RefreshToken: strings.TrimSpace(payload.RefreshToken),
	}
	if payload.ExpiresIn > 0 {
		tokens.Expiry = time.Now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second)
	}
	return tokens, nil
}

func (provider configuredOAuthProvider) FetchProfile(ctx context.Context, accessToken string) (OAuthProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.config.UserInfoURL, nil)
	if err != nil {
		return OAuthProfile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := provider.httpClient.Do(req)
	if err != nil {
		return OAuthProfile{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return OAuthProfile{}, fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return OAuthProfile{}, err
	}

	profile := OAuthProfile{
		Subject:       payloadString(payload, provider.config.SubjectField),
		Email:         strings.ToLower(strings.TrimSpace(payloadString(payload, provider.config.EmailField))),
		EmailVerified: payloadBool(payload, provider.config.EmailVerifiedField, true),
		Username:      payloadString(payload, provider.config.UsernameField),
		Name:          payloadString(payload, provider.config.NameField),
	}
	return profile, nil
}

func (s *Service) completeOAuthFlow(ctx context.Context, queries *sqlc.Queries, provider string, flowState oauthFlowState, profile OAuthProfile, tokens OAuthTokens) (SessionPrincipal, OAuthAuthenticationResult, error) {
	result := OAuthAuthenticationResult{Provider: provider, Mode: modeForUserID(flowState.LinkUserID)}

	account, err := queries.GetOAuthAccountByProviderIdentity(ctx, sqlc.GetOAuthAccountByProviderIdentityParams{
		Provider:       provider,
		ProviderUserID: strings.TrimSpace(profile.Subject),
	})
	if err != nil && !errorsIsNoRows(err) {
		return SessionPrincipal{}, OAuthAuthenticationResult{}, err
	}

	userID := flowState.LinkUserID
	if err == nil {
		if flowState.LinkUserID != 0 && account.UserID != flowState.LinkUserID {
			return SessionPrincipal{}, OAuthAuthenticationResult{}, ErrOAuthConflict
		}
		userID = account.UserID
	} else if flowState.LinkUserID == 0 {
		matchedUser, lookupErr := queries.GetUserByEmail(ctx, profile.Email)
		if lookupErr == nil {
			if !matchedUser.IsActive {
				return SessionPrincipal{}, OAuthAuthenticationResult{}, ErrAccountDisabled
			}
			if matchedUser.LockedUntil.Valid && matchedUser.LockedUntil.Time.After(time.Now().UTC()) {
				return SessionPrincipal{}, OAuthAuthenticationResult{}, ErrAccountLocked
			}
			userID = matchedUser.ID
			result.Linked = true
		} else if !errorsIsNoRows(lookupErr) {
			return SessionPrincipal{}, OAuthAuthenticationResult{}, lookupErr
		} else {
			createdUser, createErr := s.createOAuthUser(ctx, queries, provider, profile)
			if createErr != nil {
				return SessionPrincipal{}, OAuthAuthenticationResult{}, createErr
			}
			userID = createdUser.ID
			result.Created = true
		}
	}

	if flowState.LinkUserID != 0 {
		existingProviderAccount, existingErr := queries.GetOAuthAccountByUserIDAndProvider(ctx, sqlc.GetOAuthAccountByUserIDAndProviderParams{UserID: flowState.LinkUserID, Provider: provider})
		if existingErr == nil && existingProviderAccount.ProviderUserID != strings.TrimSpace(profile.Subject) {
			return SessionPrincipal{}, OAuthAuthenticationResult{}, ErrOAuthConflict
		}
		if existingErr != nil && !errorsIsNoRows(existingErr) {
			return SessionPrincipal{}, OAuthAuthenticationResult{}, existingErr
		}
		result.Linked = true
	}

	sealedAccessToken, err := sealStoredSecret(tokens.AccessToken, s.cfg.Security.EncryptionKey)
	if err != nil {
		return SessionPrincipal{}, OAuthAuthenticationResult{}, err
	}
	sealedRefreshToken := []byte(nil)
	if tokens.RefreshToken != "" {
		sealedRefreshToken, err = sealStoredSecret(tokens.RefreshToken, s.cfg.Security.EncryptionKey)
		if err != nil {
			return SessionPrincipal{}, OAuthAuthenticationResult{}, err
		}
	}

	if _, err := queries.UpsertOAuthAccount(ctx, sqlc.UpsertOAuthAccountParams{
		UserID:                 userID,
		Provider:               provider,
		ProviderUserID:         strings.TrimSpace(profile.Subject),
		AccessTokenCiphertext:  sealedAccessToken,
		RefreshTokenCiphertext: sealedRefreshToken,
		TokenExpiresAt:         nullTime(tokens.Expiry),
	}); err != nil {
		return SessionPrincipal{}, OAuthAuthenticationResult{}, err
	}

	principal, err := s.completeUserAuthentication(ctx, queries, userID, flowState.LinkUserID == 0)
	if err != nil {
		return SessionPrincipal{}, OAuthAuthenticationResult{}, err
	}
	return principal, result, nil
}

func (s *Service) createOAuthUser(ctx context.Context, queries *sqlc.Queries, provider string, profile OAuthProfile) (sqlc.User, error) {
	if strings.TrimSpace(profile.Email) == "" {
		return sqlc.User{}, ErrOAuthProfile
	}

	createdUser, err := queries.CreateUser(ctx, sqlc.CreateUserParams{
		Username: generateOAuthUsername(provider, profile),
		Email:    strings.TrimSpace(profile.Email),
	})
	if err != nil {
		return sqlc.User{}, err
	}
	if profile.EmailVerified {
		if err := queries.MarkUserEmailVerified(ctx, createdUser.ID); err != nil {
			return sqlc.User{}, err
		}
		createdUser.EmailVerifiedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	}

	role, err := queries.GetRoleByName(ctx, "user")
	if err != nil {
		return sqlc.User{}, err
	}
	if err := queries.AddUserRole(ctx, sqlc.AddUserRoleParams{UserID: createdUser.ID, RoleID: role.ID}); err != nil {
		return sqlc.User{}, err
	}

	return createdUser, nil
}

func applyOAuthProviderDefaults(cfg config.OAuthProviderConfig) config.OAuthProviderConfig {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	if cfg.SubjectField == "" {
		cfg.SubjectField = "sub"
	}
	if cfg.EmailField == "" {
		cfg.EmailField = "email"
	}
	if cfg.EmailVerifiedField == "" {
		cfg.EmailVerifiedField = "email_verified"
	}
	if cfg.UsernameField == "" {
		cfg.UsernameField = "preferred_username"
	}
	if cfg.NameField == "" {
		cfg.NameField = "name"
	}
	return cfg
}

func encodeOAuthFlow(state oauthFlowState) ([]byte, error) {
	return json.Marshal(state)
}

func decodeOAuthFlow(sessionJSON []byte) (oauthFlowState, error) {
	if len(strings.TrimSpace(string(sessionJSON))) == 0 {
		return oauthFlowState{}, ErrOAuthState
	}

	var state oauthFlowState
	if err := json.Unmarshal(sessionJSON, &state); err != nil {
		return oauthFlowState{}, ErrOAuthState
	}
	return state, nil
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func pkceCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func sealStoredSecret(value string, key string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	ciphertext, nonce, err := encryptSecret(value, key)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	return sealed, nil
}

func subtleCompare(left string, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func payloadString(payload map[string]any, field string) string {
	value, ok := payload[field]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func payloadBool(payload map[string]any, field string, defaultValue bool) bool {
	if strings.TrimSpace(field) == "" {
		return defaultValue
	}
	value, ok := payload[field]
	if !ok {
		return defaultValue
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return defaultValue
	}
}

func generateOAuthUsername(provider string, profile OAuthProfile) string {
	baseValue := profile.Username
	if baseValue == "" {
		baseValue = profile.Name
	}
	if baseValue == "" {
		baseValue = strings.Split(profile.Email, "@")[0]
	}
	baseValue = sanitizeUsername(baseValue)
	if baseValue == "" {
		baseValue = provider
	}
	uniqueSuffix, err := randomToken(4)
	if err != nil {
		return fmt.Sprintf("%s-user", baseValue)
	}
	return fmt.Sprintf("%s-%s", baseValue, strings.ToLower(uniqueSuffix[:6]))
}

func sanitizeUsername(value string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		case char == '-', char == '_', char == '.':
			builder.WriteRune(char)
		}
	}
	return strings.Trim(builder.String(), "-._")
}

func modeForUserID(userID int64) string {
	if userID != 0 {
		return "link"
	}
	return "login"
}

func errorsIsNoRows(err error) bool {
	return err != nil && err == sql.ErrNoRows
}

func nullTime(value time.Time) sql.NullTime {
	if value.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}
