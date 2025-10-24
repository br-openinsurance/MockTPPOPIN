package tpp

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func (t *TPP) InitSession(ctx context.Context) (session *Session, authURL string, err error) {
	authURL, codeVerifier, err := t.directoryAuthURL(ctx, "openid trust_framework_profile")
	if err != nil {
		return nil, "", err
	}

	session = &Session{
		ID:           uuid.NewString(),
		CodeVerifier: codeVerifier,
		ExpiresAt:    timestampNow() + 10*60, // 10 minutes.
		CreatedAt:    timestampNow(),
	}
	if err := t.saveSession(ctx, session); err != nil {
		return nil, "", err
	}

	return session, authURL, nil
}

func (t *TPP) AuthorizeSession(ctx context.Context, session *Session, response string) error {
	idTkn, err := t.directoryIDToken(ctx, response, session.CodeVerifier)
	if err != nil {
		return err
	}

	session.UserID = idTkn.Sub
	session.ExpiresAt = session.CreatedAt + 60*60
	session.CodeVerifier = ""
	for orgID := range idTkn.Profile.OrgAccessDetails {
		session.OrganizationIDs = append(session.OrganizationIDs, strings.ReplaceAll(orgID, "_", "-"))
	}

	return t.saveSession(ctx, session)
}

func (t *TPP) Session(ctx context.Context, id string) (*Session, error) {
	var session Session
	if err := t.storage.fetch(ctx, id, &session); err != nil {
		return nil, fmt.Errorf("could not get session: %w", err)
	}

	if session.IsExpired() {
		return nil, fmt.Errorf("session expired: %w", ErrNotFound)
	}
	return &session, nil
}

func (t *TPP) saveSession(ctx context.Context, session *Session) error {
	if err := t.storage.save(ctx, session); err != nil {
		return fmt.Errorf("could not save session: %w", err)
	}
	return nil
}
