package tpp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
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

// Helper function to create a mock TPP with test servers
func setupMockTPP(t *testing.T, apiType APIType, apiVersion string, responseData map[string]any) (*TPP, *Flow, func()) {
	flow := &Flow{
		APIType:       apiType,
		APIVersion:    apiVersion,
		AuthCodeToken: "test-token",
		ID:            "test-flow-id",
		OrgID:         "test-org",
		AuthServerID:  "auth1",
		ClientID:      "test-client-id",
	}

	apiServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responseData)
	}))

	// Mock OpenID config server with token endpoint
	var openIDConfigServerURL string
	openIDConfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			config := OpenIDConfiguration{
				Issuer:             openIDConfigServerURL,
				AuthEndpoint:       openIDConfigServerURL + "/authorize",
				EndSessionEndpoint: openIDConfigServerURL + "/end-session",
				JWKSURI:            openIDConfigServerURL + "/jwks",
				TokenEndpoint:      openIDConfigServerURL + "/token",
				IDTokenSigAlgs:     []jose.SignatureAlgorithm{jose.RS256},
				MTLS: struct {
					PushedAuthEndpoint   string `json:"pushed_authorization_request_endpoint"`
					TokenEndpoint        string `json:"token_endpoint"`
					RegistrationEndpoint string `json:"registration_endpoint"`
				}{
					PushedAuthEndpoint:   openIDConfigServerURL + "/par",
					TokenEndpoint:        openIDConfigServerURL + "/token",
					RegistrationEndpoint: openIDConfigServerURL + "/register",
				},
			}
			json.NewEncoder(w).Encode(config)
			return
		}
		if r.URL.Path == "/token" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			tokenResponse := map[string]any{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			json.NewEncoder(w).Encode(tokenResponse)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	openIDConfigServerURL = openIDConfigServer.URL

	participantsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		participants := []Participant{
			{
				OrgID: flow.OrgID,
				Name:  "Test Organization",
				AuthServers: []AuthServer{
					{
						ID:              "auth1",
						OrgID:           flow.OrgID,
						Name:            "Test Auth Server",
						OpenIDConfigURL: openIDConfigServer.URL + "/.well-known/openid-configuration",
						Resources: []struct {
							APIType            APIType `json:"ApiFamilyType"`
							Version            string  `json:"ApiVersion"`
							Status             string  `json:"Status"`
							DiscoveryEndpoints []struct {
								Endpoint string `json:"ApiEndpoint"`
							} `json:"ApiDiscoveryEndpoints"`
						}{
							{
								APIType: apiType,
								Version: apiVersion,
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: apiServer.URL + "/open-insurance"},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(participants)
	}))

	mockStorage := &MockStorage{store: make(map[string]Item)}
	tpp := &TPP{
		orgID:                 flow.OrgID,
		participantsURL:       participantsServer.URL,
		participantMTLSClient: apiServer.Client(),
		storage:               mockStorage,
		jwtSignerID:           "test-signer-id",
		jwtSigner:             generateTestKey(t),
	}

	cleanup := func() {
		apiServer.Close()
		openIDConfigServer.Close()
		participantsServer.Close()
	}

	return tpp, flow, cleanup
}

// Test Resources happy path
func TestTPP_Resources_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"id": "resource1", "type": "account"},
			{"id": "resource2", "type": "transaction"},
		},
		"meta": map[string]any{
			"totalPages": 1,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeResources, "1.0", responseData)
	defer cleanup()

	result, err := tpp.Resources(context.Background(), flow, "10", "1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CustomersPersonalIdentifications happy path
func TestTPP_CustomersPersonalIdentifications_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"cpf":  "12345678900",
			"name": "John Doe",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCustomersPersonal, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CustomersPersonalIdentifications(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CustomersPersonalAdditionalInfo happy path
func TestTPP_CustomersPersonalAdditionalInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"email": "john@example.com",
			"phone": "+5511999999999",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCustomersPersonal, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CustomersPersonalAdditionalInfo(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CustomersPersonalQualifications happy path
func TestTPP_CustomersPersonalQualifications_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"education":  "Bachelor's Degree",
			"occupation": "Software Engineer",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCustomersPersonal, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CustomersPersonalQualifications(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CustomersBusinessIdentifications happy path
func TestTPP_CustomersBusinessIdentifications_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"cnpj":        "12345678000190",
			"companyName": "Example Corp",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCustomersBusiness, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CustomersBusinessIdentifications(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CustomersBusinessAdditionalInfo happy path
func TestTPP_CustomersBusinessAdditionalInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"email": "contact@example.com",
			"phone": "+5511888888888",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCustomersBusiness, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CustomersBusinessAdditionalInfo(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CustomersBusinessQualifications happy path
func TestTPP_CustomersBusinessQualifications_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"industry": "Technology",
			"size":     "Medium",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCustomersBusiness, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CustomersBusinessQualifications(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AutoPolicies happy path
func TestTPP_AutoPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1", "status": "active"},
			{"policyId": "pol2", "status": "active"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAuto, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AutoPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AutoPolicyInfo happy path
func TestTPP_AutoPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
			"coverage": "Full",
			"premium":  1000.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAuto, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AutoPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AutoPolicyPremium happy path
func TestTPP_AutoPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium":  1000.00,
			"currency": "BRL",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAuto, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AutoPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AutoPolicyClaims happy path
func TestTPP_AutoPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1", "status": "pending"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAuto, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AutoPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test HousingPolicies happy path
func TestTPP_HousingPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1", "status": "active"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeHousing, "1.0", responseData)
	defer cleanup()

	result, err := tpp.HousingPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test HousingPolicyInfo happy path
func TestTPP_HousingPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
			"coverage": "Full",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeHousing, "1.0", responseData)
	defer cleanup()

	result, err := tpp.HousingPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test HousingPolicyPremium happy path
func TestTPP_HousingPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 2000.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeHousing, "1.0", responseData)
	defer cleanup()

	result, err := tpp.HousingPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test HousingPolicyClaims happy path
func TestTPP_HousingPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeHousing, "1.0", responseData)
	defer cleanup()

	result, err := tpp.HousingPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PatrimonialPolicies happy path
func TestTPP_PatrimonialPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePatrimonial, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PatrimonialPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PatrimonialPolicyInfo happy path
func TestTPP_PatrimonialPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePatrimonial, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PatrimonialPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PatrimonialPolicyPremium happy path
func TestTPP_PatrimonialPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 1500.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePatrimonial, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PatrimonialPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PatrimonialPolicyClaims happy path
func TestTPP_PatrimonialPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePatrimonial, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PatrimonialPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PersonPolicies happy path
func TestTPP_PersonPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePerson, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PersonPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PersonPolicyInfo happy path
func TestTPP_PersonPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePerson, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PersonPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PersonPolicyPremium happy path
func TestTPP_PersonPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 800.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePerson, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PersonPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PersonPolicyClaims happy path
func TestTPP_PersonPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePerson, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PersonPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test FinancialAssistanceContracts happy path
func TestTPP_FinancialAssistanceContracts_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"contractId": "contract1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeFinancialAssistance, "1.0", responseData)
	defer cleanup()

	result, err := tpp.FinancialAssistanceContracts(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test FinancialAssistanceContractInfo happy path
func TestTPP_FinancialAssistanceContractInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"contractId": "contract1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeFinancialAssistance, "1.0", responseData)
	defer cleanup()

	result, err := tpp.FinancialAssistanceContractInfo(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test FinancialAssistanceContractMovements happy path
func TestTPP_FinancialAssistanceContractMovements_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"movementId": "mov1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeFinancialAssistance, "1.0", responseData)
	defer cleanup()

	result, err := tpp.FinancialAssistanceContractMovements(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CapitalizationTitlePlans happy path
func TestTPP_CapitalizationTitlePlans_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"planId": "plan1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCapitalizationTitle, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CapitalizationTitlePlans(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CapitalizationTitlePlanInfo happy path
func TestTPP_CapitalizationTitlePlanInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"planId": "plan1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCapitalizationTitle, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CapitalizationTitlePlanInfo(context.Background(), flow, "plan1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CapitalizationTitlePlanEvents happy path
func TestTPP_CapitalizationTitlePlanEvents_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"eventId": "event1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCapitalizationTitle, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CapitalizationTitlePlanEvents(context.Background(), flow, "plan1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CapitalizationTitlePlanSettlements happy path
func TestTPP_CapitalizationTitlePlanSettlements_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"settlementId": "settlement1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeCapitalizationTitle, "1.0", responseData)
	defer cleanup()

	result, err := tpp.CapitalizationTitlePlanSettlements(context.Background(), flow, "plan1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test LifePensionContracts happy path
func TestTPP_LifePensionContracts_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"contractId": "contract1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeLifePension, "1.0", responseData)
	defer cleanup()

	result, err := tpp.LifePensionContracts(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test LifePensionContractInfo happy path
func TestTPP_LifePensionContractInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"contractId": "contract1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeLifePension, "1.0", responseData)
	defer cleanup()

	result, err := tpp.LifePensionContractInfo(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test LifePensionContractMovements happy path
func TestTPP_LifePensionContractMovements_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"movementId": "mov1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeLifePension, "1.0", responseData)
	defer cleanup()

	result, err := tpp.LifePensionContractMovements(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test LifePensionContractPortabilities happy path
func TestTPP_LifePensionContractPortabilities_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"portabilityId": "port1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeLifePension, "1.0", responseData)
	defer cleanup()

	result, err := tpp.LifePensionContractPortabilities(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test LifePensionContractWithdrawals happy path
func TestTPP_LifePensionContractWithdrawals_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"withdrawalId": "with1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeLifePension, "1.0", responseData)
	defer cleanup()

	result, err := tpp.LifePensionContractWithdrawals(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test LifePensionContractClaim happy path
func TestTPP_LifePensionContractClaim_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"claimId": "claim1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeLifePension, "1.0", responseData)
	defer cleanup()

	result, err := tpp.LifePensionContractClaim(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PensionPlanContracts happy path
func TestTPP_PensionPlanContracts_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"contractId": "contract1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePensionPlan, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PensionPlanContracts(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PensionPlanContractInfo happy path
func TestTPP_PensionPlanContractInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"contractId": "contract1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePensionPlan, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PensionPlanContractInfo(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PensionPlanContractMovements happy path
func TestTPP_PensionPlanContractMovements_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"movementId": "mov1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePensionPlan, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PensionPlanContractMovements(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PensionPlanContractPortabilities happy path
func TestTPP_PensionPlanContractPortabilities_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"portabilityId": "port1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePensionPlan, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PensionPlanContractPortabilities(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PensionPlanContractWithdrawals happy path
func TestTPP_PensionPlanContractWithdrawals_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"withdrawalId": "with1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePensionPlan, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PensionPlanContractWithdrawals(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test PensionPlanContractClaim happy path
func TestTPP_PensionPlanContractClaim_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"claimId": "claim1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypePensionPlan, "1.0", responseData)
	defer cleanup()

	result, err := tpp.PensionPlanContractClaim(context.Background(), flow, "contract1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test DynamicFieldsDamageAndPerson happy path
func TestTPP_DynamicFieldsDamageAndPerson_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"fields": []map[string]any{
				{"name": "field1", "type": "string"},
			},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeDynamicFields, "1.0", responseData)
	defer cleanup()

	result, err := tpp.DynamicFieldsDamageAndPerson(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test DynamicFieldsCapitalizationTitle happy path
func TestTPP_DynamicFieldsCapitalizationTitle_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"fields": []map[string]any{
				{"name": "field1", "type": "string"},
			},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeDynamicFields, "1.0", responseData)
	defer cleanup()

	result, err := tpp.DynamicFieldsCapitalizationTitle(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AcceptanceAndBranchesAbroadPolicies happy path
func TestTPP_AcceptanceAndBranchesAbroadPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAcceptanceAndBranchesAbroad, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AcceptanceAndBranchesAbroadPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AcceptanceAndBranchesAbroadPolicyInfo happy path
func TestTPP_AcceptanceAndBranchesAbroadPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAcceptanceAndBranchesAbroad, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AcceptanceAndBranchesAbroadPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AcceptanceAndBranchesAbroadPolicyPremium happy path
func TestTPP_AcceptanceAndBranchesAbroadPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 1200.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAcceptanceAndBranchesAbroad, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AcceptanceAndBranchesAbroadPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test AcceptanceAndBranchesAbroadPolicyClaims happy path
func TestTPP_AcceptanceAndBranchesAbroadPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeAcceptanceAndBranchesAbroad, "1.0", responseData)
	defer cleanup()

	result, err := tpp.AcceptanceAndBranchesAbroadPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test ResponsibilityPolicies happy path
func TestTPP_ResponsibilityPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeResponsibility, "1.0", responseData)
	defer cleanup()

	result, err := tpp.ResponsibilityPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test ResponsibilityPolicyInfo happy path
func TestTPP_ResponsibilityPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeResponsibility, "1.0", responseData)
	defer cleanup()

	result, err := tpp.ResponsibilityPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test ResponsibilityPolicyPremium happy path
func TestTPP_ResponsibilityPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 900.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeResponsibility, "1.0", responseData)
	defer cleanup()

	result, err := tpp.ResponsibilityPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test ResponsibilityPolicyClaims happy path
func TestTPP_ResponsibilityPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeResponsibility, "1.0", responseData)
	defer cleanup()

	result, err := tpp.ResponsibilityPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test RuralPolicies happy path
func TestTPP_RuralPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeRural, "1.0", responseData)
	defer cleanup()

	result, err := tpp.RuralPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test RuralPolicyInfo happy path
func TestTPP_RuralPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeRural, "1.0", responseData)
	defer cleanup()

	result, err := tpp.RuralPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test RuralPolicyPremium happy path
func TestTPP_RuralPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 1100.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeRural, "1.0", responseData)
	defer cleanup()

	result, err := tpp.RuralPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test RuralPolicyClaims happy path
func TestTPP_RuralPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeRural, "1.0", responseData)
	defer cleanup()

	result, err := tpp.RuralPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test TransportPolicies happy path
func TestTPP_TransportPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeTransport, "1.0", responseData)
	defer cleanup()

	result, err := tpp.TransportPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test TransportPolicyInfo happy path
func TestTPP_TransportPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeTransport, "1.0", responseData)
	defer cleanup()

	result, err := tpp.TransportPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test TransportPolicyPremium happy path
func TestTPP_TransportPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 1300.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeTransport, "1.0", responseData)
	defer cleanup()

	result, err := tpp.TransportPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test TransportPolicyClaims happy path
func TestTPP_TransportPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeTransport, "1.0", responseData)
	defer cleanup()

	result, err := tpp.TransportPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test FinancialRiskPolicies happy path
func TestTPP_FinancialRiskPolicies_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"policyId": "pol1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeFinancialRisk, "1.0", responseData)
	defer cleanup()

	result, err := tpp.FinancialRiskPolicies(context.Background(), flow)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test FinancialRiskPolicyInfo happy path
func TestTPP_FinancialRiskPolicyInfo_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"policyId": "pol1",
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeFinancialRisk, "1.0", responseData)
	defer cleanup()

	result, err := tpp.FinancialRiskPolicyInfo(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test FinancialRiskPolicyPremium happy path
func TestTPP_FinancialRiskPolicyPremium_Success(t *testing.T) {
	responseData := map[string]any{
		"data": map[string]any{
			"premium": 1400.00,
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeFinancialRisk, "1.0", responseData)
	defer cleanup()

	result, err := tpp.FinancialRiskPolicyPremium(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test FinancialRiskPolicyClaims happy path
func TestTPP_FinancialRiskPolicyClaims_Success(t *testing.T) {
	responseData := map[string]any{
		"data": []map[string]any{
			{"claimId": "claim1"},
		},
	}

	tpp, flow, cleanup := setupMockTPP(t, APITypeFinancialRisk, "1.0", responseData)
	defer cleanup()

	result, err := tpp.FinancialRiskPolicyClaims(context.Background(), flow, "pol1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Helper function to setup mock TPP with token endpoint for quote/consent operations
func setupMockTPPWithToken(t *testing.T, apiType APIType, apiVersion string, quoteResponse map[string]any) (*TPP, *Flow, func()) {
	flow := &Flow{
		APIType:       apiType,
		APIVersion:    apiVersion,
		AuthCodeToken: "test-token",
		ID:            "test-flow-id",
		OrgID:         "test-org",
		AuthServerID:  "auth1",
		ClientID:      "test-client-id",
	}

	// Mock token endpoint
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
		})
	}))

	// Mock quote/consent endpoint
	apiServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		json.NewEncoder(w).Encode(quoteResponse)
	}))

	// Mock OpenID config endpoint
	openIDConfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		config := OpenIDConfiguration{
			Issuer:        "https://test-issuer.example.com",
			TokenEndpoint: tokenServer.URL,
			MTLS: struct {
				PushedAuthEndpoint   string `json:"pushed_authorization_request_endpoint"`
				TokenEndpoint        string `json:"token_endpoint"`
				RegistrationEndpoint string `json:"registration_endpoint"`
			}{
				TokenEndpoint: tokenServer.URL,
			},
		}
		json.NewEncoder(w).Encode(config)
	}))

	participantsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		participants := []Participant{
			{
				OrgID: flow.OrgID,
				Name:  "Test Organization",
				AuthServers: []AuthServer{
					{
						ID:              "auth1",
						OrgID:           flow.OrgID,
						Name:            "Test Auth Server",
						OpenIDConfigURL: openIDConfigServer.URL,
						Resources: []struct {
							APIType            APIType `json:"ApiFamilyType"`
							Version            string  `json:"ApiVersion"`
							Status             string  `json:"Status"`
							DiscoveryEndpoints []struct {
								Endpoint string `json:"ApiEndpoint"`
							} `json:"ApiDiscoveryEndpoints"`
						}{
							{
								APIType: apiType,
								Version: apiVersion,
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: apiServer.URL + "/open-insurance"},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(participants)
	}))

	mockStorage := &MockStorage{
		store: map[string]Item{
			"auth1": &Client{
				AuthServerID: "auth1",
				ClientID:     "test-client-id",
			},
		},
	}

	tpp := &TPP{
		orgID:                  flow.OrgID,
		participantsURL:        participantsServer.URL,
		participantMTLSClient:  apiServer.Client(),
		storage:                mockStorage,
		participantRedirectURI: "https://redirect.example.com",
		jwtSignerID:            "test-signer-id",
		jwtSigner:              generateTestKey(t),
	}

	cleanup := func() {
		tokenServer.Close()
		apiServer.Close()
		openIDConfigServer.Close()
		participantsServer.Close()
	}

	return tpp, flow, cleanup
}

// Test CreateQuoteAutoLead happy path
func TestTPP_CreateQuoteAutoLead_Success(t *testing.T) {
	quoteData := map[string]any{
		"data": map[string]any{
			"consentId": "consent1",
			"quoteId":   "quote1",
		},
	}

	tpp, flow, cleanup := setupMockTPPWithToken(t, APITypeQuoteAuto, "1.0", quoteData)
	defer cleanup()

	requestData := map[string]any{
		"vehicle": map[string]any{
			"licensePlate": "ABC1234",
		},
	}

	result, err := tpp.CreateQuoteAutoLead(context.Background(), flow, requestData)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CreateQuotePatrimonialLead happy path
func TestTPP_CreateQuotePatrimonialLead_Success(t *testing.T) {
	quoteData := map[string]any{
		"data": map[string]any{
			"consentId": "consent1",
			"quoteId":   "quote1",
		},
	}

	tpp, flow, cleanup := setupMockTPPWithToken(t, APITypeQuotePatrimonialHome, "1.0", quoteData)
	defer cleanup()

	requestData := map[string]any{
		"property": map[string]any{
			"address": "123 Main St",
		},
	}

	result, err := tpp.CreateQuotePatrimonialLead(context.Background(), flow, requestData)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test CreateQuotePersonLife happy path
func TestTPP_CreateQuotePersonLife_Success(t *testing.T) {
	quoteData := map[string]any{
		"data": map[string]any{
			"consentId": "consent1",
			"quoteId":   "quote1",
		},
	}

	tpp, flow, cleanup := setupMockTPPWithToken(t, APITypeQuotePersonLife, "1.0", quoteData)
	defer cleanup()

	requestData := map[string]any{
		"insured": map[string]any{
			"age": 30,
		},
	}

	result, err := tpp.CreateQuotePersonLife(context.Background(), flow, requestData)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}

// Test QuoteAuto happy path
func TestTPP_QuoteAuto_Success(t *testing.T) {
	quoteStatusData := map[string]any{
		"data": map[string]any{
			"status": "completed",
			"quote": map[string]any{
				"premium": 1000.00,
			},
		},
	}

	tpp, flow, cleanup := setupMockTPPWithToken(t, APITypeQuoteAuto, "1.0", quoteStatusData)
	defer cleanup()

	result, err := tpp.QuoteAuto(context.Background(), flow, "consent1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}
}
