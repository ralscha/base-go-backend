package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"base/internal/store/sqlc"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID int64) (*protocol.CredentialCreation, []byte, error) {
	user, err := s.loadPasskeyUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	options, session, err := s.webAuthn.BeginRegistration(
		user,
		wa.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		wa.WithExclusions(wa.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
		wa.WithExtensions(map[string]any{"credProps": true}),
	)
	if err != nil {
		return nil, nil, err
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal passkey registration session: %w", err)
	}

	return options, sessionJSON, nil
}

func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID int64, sessionJSON, credentialJSON []byte, name string) error {
	session, err := decodePasskeySession(sessionJSON)
	if err != nil {
		return err
	}

	user, err := s.loadPasskeyUser(ctx, userID)
	if err != nil {
		return err
	}

	credential, err := s.webAuthn.FinishRegistration(user, *session, jsonRequest(credentialJSON))
	if err != nil {
		return err
	}

	return s.persistPasskeyCredential(ctx, userID, credential, strings.TrimSpace(name))
}

func (s *Service) BeginPasskeyLogin() (*protocol.CredentialAssertion, []byte, error) {
	options, session, err := s.webAuthn.BeginDiscoverableLogin(wa.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return nil, nil, err
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal passkey login session: %w", err)
	}

	return options, sessionJSON, nil
}

func (s *Service) FinishPasskeyLogin(ctx context.Context, sessionJSON, credentialJSON []byte, totpCode string) (SessionPrincipal, error) {
	session, err := decodePasskeySession(sessionJSON)
	if err != nil {
		return SessionPrincipal{}, err
	}

	validatedUser, validatedCredential, err := s.webAuthn.FinishPasskeyLogin(func(rawID, userHandle []byte) (wa.User, error) {
		return s.loadPasskeyUserByHandle(ctx, rawID, userHandle)
	}, *session, jsonRequest(credentialJSON))
	if err != nil {
		return SessionPrincipal{}, err
	}

	user, ok := validatedUser.(*passkeyUser)
	if !ok {
		return SessionPrincipal{}, errors.New("unexpected passkey user type")
	}

	if err := s.validateSecondFactor(ctx, user.user.ID, totpCode); err != nil {
		return SessionPrincipal{}, err
	}
	if err := s.queries.UpdateUserLastLogin(ctx, user.user.ID); err != nil {
		return SessionPrincipal{}, err
	}
	if err := s.updatePasskeyCredential(ctx, validatedCredential); err != nil {
		return SessionPrincipal{}, err
	}

	return s.completeUserAuthentication(ctx, s.queries, user.user.ID, true)
}

type passkeyUser struct {
	user        sqlc.User
	credentials []wa.Credential
}

func (u *passkeyUser) WebAuthnID() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(u.user.ID)) //nolint:gosec // user IDs are always positive
	return buf
}

func (u *passkeyUser) WebAuthnName() string {
	return u.user.Username
}

func (u *passkeyUser) WebAuthnDisplayName() string {
	return u.user.Email
}

func (u *passkeyUser) WebAuthnCredentials() []wa.Credential {
	return u.credentials
}

func (s *Service) loadPasskeyUser(ctx context.Context, userID int64) (*passkeyUser, error) {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	credentialRows, err := s.queries.ListPasskeyCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	credentials := make([]wa.Credential, 0, len(credentialRows))
	for _, row := range credentialRows {
		credential := credentialFromRow(row)
		credentials = append(credentials, credential)
	}

	return &passkeyUser{user: user, credentials: credentials}, nil
}

func (s *Service) loadPasskeyUserByHandle(ctx context.Context, rawID, userHandle []byte) (*passkeyUser, error) {
	if len(userHandle) != 8 {
		return nil, errors.New("invalid user handle")
	}

	userID := int64(binary.BigEndian.Uint64(userHandle)) //nolint:gosec // reversing the WebAuthn user handle encoding
	user, err := s.loadPasskeyUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	for _, credential := range user.credentials {
		if bytes.Equal(credential.ID, rawID) {
			return user, nil
		}
	}

	return nil, errors.New("passkey not found for user")
}

func decodePasskeySession(sessionJSON []byte) (*wa.SessionData, error) {
	if len(bytes.TrimSpace(sessionJSON)) == 0 {
		return nil, ErrPasskeyCeremony
	}

	var session wa.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return nil, fmt.Errorf("decode passkey session: %w", err)
	}

	return &session, nil
}

func jsonRequest(body []byte) *http.Request {
	return &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(bytes.NewReader(body)),
	}
}

func (s *Service) persistPasskeyCredential(ctx context.Context, userID int64, credential *wa.Credential, name string) error {
	credentialData, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("marshal passkey credential: %w", err)
	}

	aaguid := uuid.NullUUID{}
	if len(credential.Authenticator.AAGUID) == 16 {
		parsed, err := uuid.FromBytes(credential.Authenticator.AAGUID)
		if err != nil {
			return fmt.Errorf("decode passkey aaguid: %w", err)
		}
		aaguid = uuid.NullUUID{UUID: parsed, Valid: true}
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, transport := range credential.Transport {
		transports = append(transports, string(transport))
	}

	if name == "" {
		name = "Passkey"
	}

	_, err = s.queries.CreatePasskeyCredential(ctx, sqlc.CreatePasskeyCredentialParams{
		UserID:              userID,
		CredentialID:        credential.ID,
		CredentialPublicKey: credential.PublicKey,
		AttestationType:     credential.AttestationType,
		Aaguid:              aaguid,
		SignCount:           int64(credential.Authenticator.SignCount),
		CloneWarning:        credential.Authenticator.CloneWarning,
		Transports:          transports,
		Name:                sql.NullString{String: name, Valid: true},
		CredentialData:      credentialData,
	})

	return err
}

func (s *Service) updatePasskeyCredential(ctx context.Context, credential *wa.Credential) error {
	credentialData, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("marshal updated passkey credential: %w", err)
	}

	aaguid := uuid.NullUUID{}
	if len(credential.Authenticator.AAGUID) == 16 {
		parsed, err := uuid.FromBytes(credential.Authenticator.AAGUID)
		if err != nil {
			return fmt.Errorf("decode passkey aaguid: %w", err)
		}
		aaguid = uuid.NullUUID{UUID: parsed, Valid: true}
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, transport := range credential.Transport {
		transports = append(transports, string(transport))
	}

	return s.queries.UpdatePasskeyCredential(ctx, sqlc.UpdatePasskeyCredentialParams{
		CredentialID:        credential.ID,
		CredentialPublicKey: credential.PublicKey,
		AttestationType:     credential.AttestationType,
		Aaguid:              aaguid,
		SignCount:           int64(credential.Authenticator.SignCount),
		CloneWarning:        credential.Authenticator.CloneWarning,
		Transports:          transports,
		CredentialData:      credentialData,
	})
}

func credentialFromRow(row sqlc.PasskeyCredential) wa.Credential {
	if len(row.CredentialData) > 0 && string(row.CredentialData) != "{}" {
		var credential wa.Credential
		if err := json.Unmarshal(row.CredentialData, &credential); err == nil {
			return credential
		}
	}

	credential := wa.Credential{
		ID:              row.CredentialID,
		PublicKey:       row.CredentialPublicKey,
		AttestationType: row.AttestationType,
		Transport:       make([]protocol.AuthenticatorTransport, 0, len(row.Transports)),
		Authenticator: wa.Authenticator{
			SignCount:    uint32(row.SignCount), //nolint:gosec // WebAuthn sign counter fits in uint32
			CloneWarning: row.CloneWarning,
		},
	}

	if row.Aaguid.Valid {
		credential.Authenticator.AAGUID = row.Aaguid.UUID[:]
	}
	for _, transport := range row.Transports {
		credential.Transport = append(credential.Transport, protocol.AuthenticatorTransport(transport))
	}

	return credential
}
