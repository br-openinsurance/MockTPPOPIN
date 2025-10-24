package tpp

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// Test MockStorage functionality
func TestMockStorage_SaveAndFetch(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}

	// Test saving and fetching a Flow
	flow := &Flow{
		ID:           "test-flow-id",
		UserID:       "test-user",
		APIType:      APITypeHousing,
		APIVersion:   "1.0",
		AuthServerID: "test-auth-server",
		OrgID:        "test-org",
	}

	err := mockStorage.save(context.Background(), flow)
	if err != nil {
		t.Errorf("Expected no error saving flow, got %v", err)
	}

	// Fetch the flow
	fetchedFlow := &Flow{}
	err = mockStorage.fetch(context.Background(), "test-flow-id", fetchedFlow)
	if err != nil {
		t.Errorf("Expected no error fetching flow, got %v", err)
	}

	if fetchedFlow.ID != flow.ID {
		t.Errorf("Expected flow ID %s, got %s", flow.ID, fetchedFlow.ID)
	}
	if fetchedFlow.UserID != flow.UserID {
		t.Errorf("Expected flow UserID %s, got %s", flow.UserID, fetchedFlow.UserID)
	}
	if fetchedFlow.APIType != flow.APIType {
		t.Errorf("Expected flow APIType %s, got %s", flow.APIType, fetchedFlow.APIType)
	}
}

func TestMockStorage_FetchNotFound(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}

	// Try to fetch a non-existent flow
	fetchedFlow := &Flow{}
	err := mockStorage.fetch(context.Background(), "non-existent-id", fetchedFlow)
	if err == nil {
		t.Error("Expected error when fetching non-existent item")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestMockStorage_SaveAndFetchSession(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}

	// Test saving and fetching a Session
	session := &Session{
		ID:              "test-session-id",
		UserID:          "test-user",
		IsAdmin:         true,
		OrganizationIDs: []string{"org1", "org2"},
		CodeVerifier:    "test-code-verifier",
		CreatedAt:       1234567890,
		ExpiresAt:       1234567890 + 3600,
	}

	err := mockStorage.save(context.Background(), session)
	if err != nil {
		t.Errorf("Expected no error saving session, got %v", err)
	}

	// Fetch the session
	fetchedSession := &Session{}
	err = mockStorage.fetch(context.Background(), "test-session-id", fetchedSession)
	if err != nil {
		t.Errorf("Expected no error fetching session, got %v", err)
	}

	if fetchedSession.ID != session.ID {
		t.Errorf("Expected session ID %s, got %s", session.ID, fetchedSession.ID)
	}
	if fetchedSession.UserID != session.UserID {
		t.Errorf("Expected session UserID %s, got %s", session.UserID, fetchedSession.UserID)
	}
	if fetchedSession.IsAdmin != session.IsAdmin {
		t.Errorf("Expected session IsAdmin %v, got %v", session.IsAdmin, fetchedSession.IsAdmin)
	}
	if len(fetchedSession.OrganizationIDs) != len(session.OrganizationIDs) {
		t.Errorf("Expected %d organization IDs, got %d", len(session.OrganizationIDs), len(fetchedSession.OrganizationIDs))
	}
}

func TestMockStorage_SaveAndFetchClient(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}

	// Test saving and fetching a Client
	client := &Client{
		AuthServerID:      "test-auth-server",
		ClientID:          "test-client-id",
		RegistrationToken: "test-registration-token",
	}

	err := mockStorage.save(context.Background(), client)
	if err != nil {
		t.Errorf("Expected no error saving client, got %v", err)
	}

	// Fetch the client
	fetchedClient := &Client{}
	err = mockStorage.fetch(context.Background(), "test-auth-server", fetchedClient)
	if err != nil {
		t.Errorf("Expected no error fetching client, got %v", err)
	}

	if fetchedClient.AuthServerID != client.AuthServerID {
		t.Errorf("Expected client AuthServerID %s, got %s", client.AuthServerID, fetchedClient.AuthServerID)
	}
	if fetchedClient.ClientID != client.ClientID {
		t.Errorf("Expected client ClientID %s, got %s", client.ClientID, fetchedClient.ClientID)
	}
	if fetchedClient.RegistrationToken != client.RegistrationToken {
		t.Errorf("Expected client RegistrationToken %s, got %s", client.RegistrationToken, fetchedClient.RegistrationToken)
	}
}

type MockStorage struct {
	store map[string]Item
}

func (s *MockStorage) save(_ context.Context, item Item) error {
	if s.store == nil {
		s.store = make(map[string]Item)
	}
	switch v := item.(type) {
	case *Flow:
		// Create a copy to avoid pointer issues
		flowCopy := *v
		s.store[v.ID] = &flowCopy
	case *Session:
		// Create a copy to avoid pointer issues
		sessionCopy := *v
		s.store[v.ID] = &sessionCopy
	case *Client:
		// Create a copy to avoid pointer issues
		clientCopy := *v
		s.store[v.AuthServerID] = &clientCopy
	}
	return nil
}

func (s *MockStorage) fetch(_ context.Context, id string, item Item) error {
	storedItem, ok := s.store[id]
	if !ok {
		return fmt.Errorf("item not found: %w", ErrNotFound)
	}

	// Copy the stored item data to the passed item
	switch v := item.(type) {
	case *Flow:
		if flow, ok := storedItem.(*Flow); ok {
			*v = *flow
		}
	case *Session:
		if session, ok := storedItem.(*Session); ok {
			*v = *session
		}
	case *Client:
		if client, ok := storedItem.(*Client); ok {
			*v = *client
		}
	default:
		return fmt.Errorf("unsupported item type: %T", item)
	}

	return nil
}

func (s *MockStorage) fetchAll(_ context.Context, _ string, _ string, _ Items) error {
	return nil
}
