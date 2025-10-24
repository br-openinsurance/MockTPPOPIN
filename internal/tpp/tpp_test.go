package tpp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTPP_New(t *testing.T) {
	cfg := Config{
		OrgID:                         "test-org",
		SoftwareID:                    "test-software",
		ParticipantsURL:               "https://participants.example.com",
		ParticipantRedirectURI:        "https://redirect.example.com",
		DirectoryIssuer:               "https://directory.example.com",
		DirectorySoftwareStatementURL: "https://directory.example.com/statement",
		DirectoryRedirectURI:          "https://directory.example.com/redirect",
		KeystoreURL:                   "https://keystore.example.com",
		JWTSignerID:                   "test-signer-id",
	}

	tpp := New(nil, cfg)

	if tpp.orgID != cfg.OrgID {
		t.Errorf("Expected orgID %s, got %s", cfg.OrgID, tpp.orgID)
	}
	if tpp.softwareID != cfg.SoftwareID {
		t.Errorf("Expected softwareID %s, got %s", cfg.SoftwareID, tpp.softwareID)
	}
	if tpp.participantsURL != cfg.ParticipantsURL {
		t.Errorf("Expected participantsURL %s, got %s", cfg.ParticipantsURL, tpp.participantsURL)
	}
	if tpp.participantRedirectURI != cfg.ParticipantRedirectURI {
		t.Errorf("Expected participantRedirectURI %s, got %s", cfg.ParticipantRedirectURI, tpp.participantRedirectURI)
	}
	if tpp.directoryIssuer != cfg.DirectoryIssuer {
		t.Errorf("Expected directoryIssuer %s, got %s", cfg.DirectoryIssuer, tpp.directoryIssuer)
	}
	if tpp.directoryRedirectURI != cfg.DirectoryRedirectURI {
		t.Errorf("Expected directoryRedirectURI %s, got %s", cfg.DirectoryRedirectURI, tpp.directoryRedirectURI)
	}
	if tpp.directorySoftwareStatementURL != cfg.DirectorySoftwareStatementURL {
		t.Errorf("Expected directorySoftwareStatementURL %s, got %s", cfg.DirectorySoftwareStatementURL, tpp.directorySoftwareStatementURL)
	}
	if tpp.keystoreURL != cfg.KeystoreURL {
		t.Errorf("Expected keystoreURL %s, got %s", cfg.KeystoreURL, tpp.keystoreURL)
	}
	if tpp.jwtSignerID != cfg.JWTSignerID {
		t.Errorf("Expected jwtSignerID %s, got %s", cfg.JWTSignerID, tpp.jwtSignerID)
	}
}

func TestTPP_InitFlow(t *testing.T) {
	mockStorage := &MockStorage{store: map[string]Item{
		"test-auth-server": &Client{
			AuthServerID: "test-auth-server",
			ClientID:     "test-client-id",
		},
	}}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	flow := &Flow{
		UserID:       "test-user",
		APIType:      APITypeHousing,
		APIVersion:   "1.0",
		AuthServerID: "test-auth-server",
		OrgID:        "test-org",
	}

	err := tpp.InitFlow(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if flow.ID == "" {
		t.Error("Expected flow ID to be set")
	}

	// Verify the flow was saved
	fetchedFlow := &Flow{}
	err = mockStorage.fetch(context.Background(), flow.ID, fetchedFlow)
	if err != nil {
		t.Errorf("Expected no error fetching saved flow, got %v", err)
	}

	if fetchedFlow.ID != flow.ID {
		t.Errorf("Expected fetched flow ID %s, got %s", flow.ID, fetchedFlow.ID)
	}
	if fetchedFlow.UserID != flow.UserID {
		t.Errorf("Expected fetched flow UserID %s, got %s", flow.UserID, fetchedFlow.UserID)
	}
}

func TestTPP_Flow(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	// Save a flow first
	flow := &Flow{
		ID:           "test-flow-id",
		UserID:       "test-user",
		APIType:      APITypeHousing,
		APIVersion:   "1.0",
		AuthServerID: "test-auth-server",
		OrgID:        "test-org",
	}
	mockStorage.save(context.Background(), flow)

	// Fetch the flow
	fetchedFlow, err := tpp.Flow(context.Background(), "test-flow-id")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if fetchedFlow.ID != flow.ID {
		t.Errorf("Expected flow ID %s, got %s", flow.ID, fetchedFlow.ID)
	}
	if fetchedFlow.UserID != flow.UserID {
		t.Errorf("Expected flow UserID %s, got %s", flow.UserID, fetchedFlow.UserID)
	}
}

func TestTPP_Flow_NotFound(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	// Try to fetch a non-existent flow
	_, err := tpp.Flow(context.Background(), "non-existent-id")
	if err == nil {
		t.Error("Expected error when fetching non-existent flow")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestTPP_SaveFlow(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	flow := &Flow{
		ID:            "test-flow-id",
		UserID:        "test-user",
		APIType:       APITypeHousing,
		APIVersion:    "1.0",
		AuthServerID:  "test-auth-server",
		OrgID:         "test-org",
		CodeVerifier:  "test-code-verifier",
		AuthCodeToken: "test-auth-code-token",
	}

	err := tpp.saveFlow(context.Background(), flow)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify the flow was saved
	fetchedFlow := &Flow{}
	err = mockStorage.fetch(context.Background(), flow.ID, fetchedFlow)
	if err != nil {
		t.Errorf("Expected no error fetching saved flow, got %v", err)
	}

	if fetchedFlow.ID != flow.ID {
		t.Errorf("Expected fetched flow ID %s, got %s", flow.ID, fetchedFlow.ID)
	}
	if fetchedFlow.CodeVerifier != flow.CodeVerifier {
		t.Errorf("Expected fetched flow CodeVerifier %s, got %s", flow.CodeVerifier, fetchedFlow.CodeVerifier)
	}
	if fetchedFlow.AuthCodeToken != flow.AuthCodeToken {
		t.Errorf("Expected fetched flow AuthCodeToken %s, got %s", flow.AuthCodeToken, fetchedFlow.AuthCodeToken)
	}
}

func TestTPP_Session(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	session := &Session{
		ID:              "test-session-id",
		UserID:          "test-user",
		IsAdmin:         true,
		OrganizationIDs: []string{"org1", "org2"},
		CodeVerifier:    "test-code-verifier",
		CreatedAt:       1234567890,
		ExpiresAt:       9999999999,
	}
	if err := tpp.saveSession(context.Background(), session); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	fetchedSession, err := tpp.Session(context.Background(), "test-session-id")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
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
}

func TestTPP_Session_NotFound(t *testing.T) {
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    &MockStorage{store: make(map[string]Item)},
	}

	// Try to fetch a non-existent session
	_, err := tpp.Session(context.Background(), "non-existent-id")
	if err == nil {
		t.Error("Expected error when fetching non-existent session")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestTPP_SaveSession(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	session := &Session{
		ID:              "test-session-id",
		UserID:          "test-user",
		IsAdmin:         true,
		OrganizationIDs: []string{"org1", "org2"},
		CodeVerifier:    "test-code-verifier",
		CreatedAt:       1234567890,
		ExpiresAt:       1234567890 + 3600,
	}

	err := tpp.saveSession(context.Background(), session)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify the session was saved
	fetchedSession := &Session{}
	err = mockStorage.fetch(context.Background(), session.ID, fetchedSession)
	if err != nil {
		t.Errorf("Expected no error fetching saved session, got %v", err)
	}

	if fetchedSession.ID != session.ID {
		t.Errorf("Expected fetched session ID %s, got %s", session.ID, fetchedSession.ID)
	}
	if fetchedSession.IsAdmin != session.IsAdmin {
		t.Errorf("Expected fetched session IsAdmin %v, got %v", session.IsAdmin, fetchedSession.IsAdmin)
	}
}

func TestTPP_Client(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	// Save a client first
	client := &Client{
		AuthServerID:      "test-auth-server",
		ClientID:          "test-client-id",
		RegistrationToken: "test-registration-token",
	}
	mockStorage.save(context.Background(), client)

	// Fetch the client
	fetchedClient, err := tpp.client(context.Background(), "test-auth-server")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if fetchedClient.AuthServerID != client.AuthServerID {
		t.Errorf("Expected client AuthServerID %s, got %s", client.AuthServerID, fetchedClient.AuthServerID)
	}
	if fetchedClient.ClientID != client.ClientID {
		t.Errorf("Expected client ClientID %s, got %s", client.ClientID, fetchedClient.ClientID)
	}
}

func TestTPP_Client_NotFound(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	// Try to fetch a non-existent client
	_, err := tpp.client(context.Background(), "non-existent-auth-server")
	if err == nil {
		t.Error("Expected error when fetching non-existent client")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestTPP_SaveClient(t *testing.T) {
	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:      "test-org",
		softwareID: "test-software",
		storage:    mockStorage,
	}

	client := &Client{
		AuthServerID:      "test-auth-server",
		ClientID:          "test-client-id",
		RegistrationToken: "test-registration-token",
	}

	err := tpp.saveClient(context.Background(), client)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify the client was saved
	fetchedClient := &Client{}
	err = mockStorage.fetch(context.Background(), client.AuthServerID, fetchedClient)
	if err != nil {
		t.Errorf("Expected no error fetching saved client, got %v", err)
	}

	if fetchedClient.AuthServerID != client.AuthServerID {
		t.Errorf("Expected fetched client AuthServerID %s, got %s", client.AuthServerID, fetchedClient.AuthServerID)
	}
	if fetchedClient.RegistrationToken != client.RegistrationToken {
		t.Errorf("Expected fetched client RegistrationToken %s, got %s", client.RegistrationToken, fetchedClient.RegistrationToken)
	}
}

// Test data structure methods
func TestFlow_TableName(t *testing.T) {
	flow := &Flow{}
	if flow.TableName() != "flows" {
		t.Errorf("Expected table name 'flows', got %s", flow.TableName())
	}
}

func TestSession_TableName(t *testing.T) {
	session := &Session{}
	if session.TableName() != "sessions" {
		t.Errorf("Expected table name 'sessions', got %s", session.TableName())
	}
}

func TestClient_TableName(t *testing.T) {
	client := &Client{}
	if client.TableName() != "clients" {
		t.Errorf("Expected table name 'clients', got %s", client.TableName())
	}
}

func TestTPP_PollAPIData_Success(t *testing.T) {
	flow := &Flow{APIType: APITypeCustomersPersonal, APIVersion: "1.0", AuthCodeToken: "token", ID: "id", OrgID: "test-org", AuthServerID: "auth1"}

	apiServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"foo":"bar"}`))
	}))
	defer apiServer.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		participants := []Participant{
			{
				OrgID: flow.OrgID,
				Name:  "Organization 1",
				AuthServers: []AuthServer{
					{
						ID:              "auth1",
						OrgID:           flow.OrgID,
						Name:            "Auth Server 1",
						OpenIDConfigURL: "https://auth1.example.com/.well-known/openid-configuration",
						Resources: []struct {
							APIType            APIType `json:"ApiFamilyType"`
							Version            string  `json:"ApiVersion"`
							Status             string  `json:"Status"`
							DiscoveryEndpoints []struct {
								Endpoint string `json:"ApiEndpoint"`
							} `json:"ApiDiscoveryEndpoints"`
						}{
							{
								APIType: APITypeCustomersPersonal,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: apiServer.URL},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(participants)
	}))
	defer server.Close()

	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:                 flow.OrgID,
		participantsURL:       server.URL,
		participantMTLSClient: apiServer.Client(),
		storage:               mockStorage,
	}

	result, err := tpp.PollAPIData(context.Background(), flow, "/test")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result["foo"] != "bar" {
		t.Errorf("expected foo=bar, got %v", result["foo"])
	}
}

func TestTPP_PollAPIData_HTTPError(t *testing.T) {
	flow := &Flow{APIType: APITypeCustomersPersonal, APIVersion: "1.0", AuthCodeToken: "token", ID: "id", OrgID: "test-org", AuthServerID: "auth1"}

	apiServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "INVALID_REQUEST", http.StatusBadRequest)
	}))
	defer apiServer.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		participants := []Participant{
			{
				OrgID: flow.OrgID,
				Name:  "Organization 1",
				AuthServers: []AuthServer{
					{
						ID:              "auth1",
						OrgID:           flow.OrgID,
						Name:            "Auth Server 1",
						OpenIDConfigURL: "https://auth1.example.com/.well-known/openid-configuration",
						Resources: []struct {
							APIType            APIType `json:"ApiFamilyType"`
							Version            string  `json:"ApiVersion"`
							Status             string  `json:"Status"`
							DiscoveryEndpoints []struct {
								Endpoint string `json:"ApiEndpoint"`
							} `json:"ApiDiscoveryEndpoints"`
						}{
							{
								APIType: APITypeCustomersPersonal,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: apiServer.URL},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(participants)
	}))
	defer server.Close()

	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:                 flow.OrgID,
		participantsURL:       server.URL,
		participantMTLSClient: apiServer.Client(),
		storage:               mockStorage,
	}
	_, err := tpp.PollAPIData(context.Background(), flow, "/test")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
