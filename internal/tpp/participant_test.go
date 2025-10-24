package tpp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestParticipants(t *testing.T) {
	// Create a test server to mock the participants endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		participants := []Participant{
			{
				OrgID: "org1",
				Name:  "Organization 1",
				AuthServers: []AuthServer{
					{
						ID:              "auth1",
						OrgID:           "org1",
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
								APIType: APITypeHousing,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: "https://api1.example.com/housing"},
								},
							},
							{
								APIType: APITypeCustomersPersonal,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: "https://api1.example.com/customers-personal"},
								},
							},
							{
								APIType: APITypeCustomersBusiness,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: "https://api1.example.com/customers-business"},
								},
							},
						},
					},
				},
			},
			{
				OrgID: "org2",
				Name:  "Organization 2",
				AuthServers: []AuthServer{
					{
						ID:              "auth2",
						OrgID:           "org2",
						Name:            "Auth Server 2",
						OpenIDConfigURL: "https://auth2.example.com/.well-known/openid-configuration",
						Resources: []struct {
							APIType            APIType `json:"ApiFamilyType"`
							Version            string  `json:"ApiVersion"`
							Status             string  `json:"Status"`
							DiscoveryEndpoints []struct {
								Endpoint string `json:"ApiEndpoint"`
							} `json:"ApiDiscoveryEndpoints"`
						}{
							{
								APIType: APITypeConsents,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: "https://api2.example.com/consents"},
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

	tpp := &TPP{
		participantsURL: server.URL,
	}

	// Test fetching all participants
	participants, err := tpp.Participants(context.Background(), []string{"org1", "org2"})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(participants) != 2 {
		t.Errorf("Expected 2 participants, got %d", len(participants))
	}

	// Test fetching specific participant
	participant, err := tpp.participant(context.Background(), "org1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if participant.OrgID != "org1" {
		t.Errorf("Expected org ID 'org1', got %s", participant.OrgID)
	}
	if participant.Name != "Organization 1" {
		t.Errorf("Expected name 'Organization 1', got %s", participant.Name)
	}
}

func TestParticipants_Error(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tpp := &TPP{
		participantsURL: server.URL,
	}

	_, err := tpp.Participants(context.Background(), []string{"org1"})
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestAuthServer(t *testing.T) {
	// Create a test server to mock the participants endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		participants := []Participant{
			{
				OrgID: "org1",
				Name:  "Organization 1",
				AuthServers: []AuthServer{
					{
						ID:              "auth1",
						OrgID:           "org1",
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
								APIType: APITypeHousing,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: "https://api1.example.com/housing"},
								},
							},
							{
								APIType: APITypeCustomersPersonal,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: "https://api1.example.com/customers-personal"},
								},
							},
							{
								APIType: APITypeCustomersBusiness,
								Version: "1.0",
								Status:  "ACTIVE",
								DiscoveryEndpoints: []struct {
									Endpoint string `json:"ApiEndpoint"`
								}{
									{Endpoint: "https://api1.example.com/customers-business"},
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

	tpp := &TPP{
		participantsURL: server.URL,
	}

	// Test successful auth server fetch
	authServer, err := tpp.AuthServer(context.Background(), "auth1", "org1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if authServer.ID != "auth1" {
		t.Errorf("Expected auth server ID 'auth1', got %s", authServer.ID)
	}
	if authServer.Name != "Auth Server 1" {
		t.Errorf("Expected auth server name 'Auth Server 1', got %s", authServer.Name)
	}

	// Test auth server not found
	_, err = tpp.AuthServer(context.Background(), "non-existent", "org1")
	if err == nil {
		t.Error("Expected error for non-existent auth server")
	}
}

func TestParticipant_NotFound(t *testing.T) {
	// Create a test server to mock the participants endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		participants := []Participant{
			{
				OrgID:       "org1",
				Name:        "Organization 1",
				AuthServers: []AuthServer{},
			},
		}
		json.NewEncoder(w).Encode(participants)
	}))
	defer server.Close()

	tpp := &TPP{
		participantsURL: server.URL,
	}

	// Test participant not found
	_, err := tpp.participant(context.Background(), "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent participant")
	}
}

func TestParticipants_Cache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		participants := []Participant{
			{
				OrgID:       "org1",
				Name:        "Organization 1",
				AuthServers: []AuthServer{},
			},
		}
		json.NewEncoder(w).Encode(participants)
	}))
	defer server.Close()

	tpp := &TPP{
		participantsURL: server.URL,
	}

	// First call should hit the server
	_, err := tpp.Participants(context.Background(), []string{"org1"})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Second call should use cache
	_, err = tpp.Participants(context.Background(), []string{"org1"})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Should only have called the server once due to caching
	if callCount != 1 {
		t.Errorf("Expected server to be called once, got %d times", callCount)
	}
}

func TestParticipantOpenIDConfig(t *testing.T) {
	// Create a test server to mock the OpenID configuration endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := OpenIDConfiguration{
			Issuer:        "https://test.example.com",
			AuthEndpoint:  "https://test.example.com/auth",
			JWKSURI:       "https://test.example.com/jwks",
			TokenEndpoint: "https://test.example.com/token",
			MTLS: struct {
				PushedAuthEndpoint   string `json:"pushed_authorization_request_endpoint"`
				TokenEndpoint        string `json:"token_endpoint"`
				RegistrationEndpoint string `json:"registration_endpoint"`
			}{
				PushedAuthEndpoint:   "https://test.example.com/par",
				TokenEndpoint:        "https://test.example.com/token",
				RegistrationEndpoint: "https://test.example.com/register",
			},
		}
		json.NewEncoder(w).Encode(config)
	}))
	defer server.Close()

	tpp := &TPP{}

	config, err := tpp.participantOpenIDConfig(context.Background(), server.URL)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if config.Issuer != "https://test.example.com" {
		t.Errorf("Expected issuer 'https://test.example.com', got %s", config.Issuer)
	}
	if config.AuthEndpoint != "https://test.example.com/auth" {
		t.Errorf("Expected auth endpoint 'https://test.example.com/auth', got %s", config.AuthEndpoint)
	}
	if config.MTLS.PushedAuthEndpoint != "https://test.example.com/par" {
		t.Errorf("Expected PAR endpoint 'https://test.example.com/par', got %s", config.MTLS.PushedAuthEndpoint)
	}
}

func TestParticipantOpenIDConfig_Error(t *testing.T) {
	tpp := &TPP{}

	_, err := tpp.participantOpenIDConfig(context.Background(), "http://invalid-url-that-does-not-exist")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestParticipantJWKS(t *testing.T) {
	serverJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					KeyID:     "test-key-id",
					Algorithm: "PS256",
					Use:       "sig",
					Key:       generateTestKey(t).Public(),
				},
			},
		}
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Fatalf("Failed to encode JWKS: %v", err)
		}

	}))
	defer serverJWKS.Close()

	// Create a test server for the OpenID config
	serverOpenIDConfig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		config := OpenIDConfiguration{
			JWKSURI: serverJWKS.URL,
		}
		if err := json.NewEncoder(w).Encode(config); err != nil {
			t.Fatalf("Failed to encode OpenID config: %v", err)
		}
	}))
	defer serverOpenIDConfig.Close()

	tpp := &TPP{}

	jwks, err := tpp.participantJWKS(context.Background(), AuthServer{
		OpenIDConfigURL: serverOpenIDConfig.URL,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID != "test-key-id" {
		t.Errorf("Expected key ID 'test-key-id', got %s", jwks.Keys[0].KeyID)
	}
}

func TestParticipantAuthURL(t *testing.T) {

	serverPAR := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		if err := json.NewEncoder(w).Encode(map[string]any{
			"request_uri": "urn:ietf:params:oauth:request_uri:random-request-uri",
			"expires_in":  300,
		}); err != nil {
			t.Fatalf("Failed to encode PAR response: %v", err)
		}
	}))
	defer serverPAR.Close()

	serverOpenIDConfig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		config := OpenIDConfiguration{
			MTLS: struct {
				PushedAuthEndpoint   string "json:\"pushed_authorization_request_endpoint\""
				TokenEndpoint        string "json:\"token_endpoint\""
				RegistrationEndpoint string "json:\"registration_endpoint\""
			}{
				PushedAuthEndpoint: serverPAR.URL,
			},
		}
		if err := json.NewEncoder(w).Encode(config); err != nil {
			t.Fatalf("Failed to encode OpenID config: %v", err)
		}
	}))
	defer serverOpenIDConfig.Close()

	mockStorage := &MockStorage{
		store: map[string]Item{
			"test-auth-server": &Client{
				AuthServerID: "test-auth-server",
				ClientID:     "test-client-id",
			},
		},
	}
	tpp := &TPP{
		storage:               mockStorage,
		participantMTLSClient: &http.Client{},
		jwtSignerID:           "test-signer-id",
		jwtSigner:             generateTestKey(t),
		participantsCache: []Participant{{
			OrgID: "test-org",
			AuthServers: []AuthServer{{
				ID:              "test-auth-server",
				OrgID:           "test-org",
				Name:            "Test Auth Server",
				OpenIDConfigURL: serverOpenIDConfig.URL,
			}},
		}},
		participantsLastFetchedAt: time.Now().UTC(),
	}

	_, _, err := tpp.participantAuthURL(context.Background(), &Flow{
		AuthServerID: "test-auth-server",
		OrgID:        "test-org",
	}, "test-consent-id")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestParticipantDCR(t *testing.T) {

	serverDCR := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		if err := json.NewEncoder(w).Encode(map[string]any{
			"client_id":                 "test-client-id",
			"registration_access_token": "test-registration-access-token",
		}); err != nil {
			t.Fatalf("Failed to encode DCR response: %v", err)
		}
	}))
	defer serverDCR.Close()

	serverOpenIDConfig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		config := OpenIDConfiguration{
			MTLS: struct {
				PushedAuthEndpoint   string "json:\"pushed_authorization_request_endpoint\""
				TokenEndpoint        string "json:\"token_endpoint\""
				RegistrationEndpoint string "json:\"registration_endpoint\""
			}{
				RegistrationEndpoint: serverDCR.URL,
			},
		}
		if err := json.NewEncoder(w).Encode(config); err != nil {
			t.Fatalf("Failed to encode OpenID config: %v", err)
		}
	}))
	defer serverOpenIDConfig.Close()

	serverDirectoryToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
		}); err != nil {
			t.Fatalf("Failed to encode token response: %v", err)
		}
	}))
	defer serverDirectoryToken.Close()

	serverDirectorySoftwareStatement := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(map[string]any{
			"software_statement": "test-software-statement",
		}); err != nil {
			t.Fatalf("Failed to encode software statement: %v", err)
		}
	}))
	defer serverDirectorySoftwareStatement.Close()

	mockStorage := &MockStorage{
		store: make(map[string]Item),
	}
	tpp := &TPP{
		storage:               mockStorage,
		participantMTLSClient: &http.Client{},
		directoryMTLSClient:   &http.Client{},
		directoryOpenidConfigCache: &OpenIDConfiguration{
			MTLS: struct {
				PushedAuthEndpoint   string "json:\"pushed_authorization_request_endpoint\""
				TokenEndpoint        string "json:\"token_endpoint\""
				RegistrationEndpoint string "json:\"registration_endpoint\""
			}{
				TokenEndpoint: serverDirectoryToken.URL,
			},
		},
		directoryOpenidConfigLastFetchedAt: time.Now().UTC(),
		directorySoftwareStatementURL:      serverDirectorySoftwareStatement.URL,
	}

	err := tpp.ParticipantDCR(context.Background(), AuthServer{
		ID:              "test-auth-server",
		OrgID:           "test-org",
		OpenIDConfigURL: serverOpenIDConfig.URL,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	client := &Client{}
	if err := mockStorage.fetch(context.Background(), "test-auth-server", client); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if client.AuthServerID != "test-auth-server" {
		t.Errorf("Expected client AuthServerID %s, got %s", "test-auth-server", client.AuthServerID)
	}
	if client.ClientID != "test-client-id" {
		t.Errorf("Expected client ClientID %s, got %s", "test-client-id", client.ClientID)
	}
}
