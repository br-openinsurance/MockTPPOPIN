package tpp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// generateTestKey creates a test RSA key for JWT signing
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	return key
}

func TestDirectoryOpenIDConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := OpenIDConfiguration{
			Issuer:         "https://directory.example.com",
			AuthEndpoint:   "https://directory.example.com/auth",
			JWKSURI:        "https://directory.example.com/jwks",
			TokenEndpoint:  "https://directory.example.com/token",
			IDTokenSigAlgs: []jose.SignatureAlgorithm{jose.PS256},
			MTLS: struct {
				PushedAuthEndpoint   string `json:"pushed_authorization_request_endpoint"`
				TokenEndpoint        string `json:"token_endpoint"`
				RegistrationEndpoint string `json:"registration_endpoint"`
			}{
				PushedAuthEndpoint:   "https://directory.example.com/par",
				TokenEndpoint:        "https://directory.example.com/token",
				RegistrationEndpoint: "https://directory.example.com/register",
			},
		}
		json.NewEncoder(w).Encode(config)
	}))
	defer server.Close()

	tpp := &TPP{
		directoryIssuer: server.URL,
		// Initialize mutex fields to prevent panic
		directoryJWKSMu:         sync.Mutex{},
		directoryOpenidConfigMu: sync.Mutex{},
		participantsCacheMu:     sync.Mutex{},
	}

	config, err := tpp.directoryOpenIDConfig()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if config.Issuer != "https://directory.example.com" {
		t.Errorf("Expected issuer 'https://directory.example.com', got %s", config.Issuer)
	}
	if config.AuthEndpoint != "https://directory.example.com/auth" {
		t.Errorf("Expected auth endpoint 'https://directory.example.com/auth', got %s", config.AuthEndpoint)
	}
	if config.JWKSURI != "https://directory.example.com/jwks" {
		t.Errorf("Expected JWKS URI 'https://directory.example.com/jwks', got %s", config.JWKSURI)
	}
	if len(config.IDTokenSigAlgs) != 1 || config.IDTokenSigAlgs[0] != jose.PS256 {
		t.Errorf("Expected ID token signature algorithms to contain PS256")
	}
}

func TestDirectoryOpenIDConfig_Error(t *testing.T) {
	tpp := &TPP{
		directoryIssuer: "http://invalid-url-that-does-not-exist",
	}

	_, err := tpp.directoryOpenIDConfig()
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestDirectoryOpenIDConfig_Cache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		config := OpenIDConfiguration{
			Issuer:        "https://directory.example.com",
			AuthEndpoint:  "https://directory.example.com/auth",
			JWKSURI:       "https://directory.example.com/jwks",
			TokenEndpoint: "https://directory.example.com/token",
		}
		json.NewEncoder(w).Encode(config)
	}))
	defer server.Close()

	tpp := &TPP{
		directoryIssuer: server.URL,
	}

	// First call should hit the server
	_, err := tpp.directoryOpenIDConfig()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Second call should use cache
	_, err = tpp.directoryOpenIDConfig()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Should only have called the server once due to caching
	if callCount != 1 {
		t.Errorf("Expected server to be called once, got %d times", callCount)
	}
}

func TestDirectoryJWKS(t *testing.T) {
	// Create a test server to mock the JWKS endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a proper JWKS response
		jwksResponse := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"alg": "PS256",
					"use": "sig",
					"n":   "test-modulus",
					"e":   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	// Create a test server for the OpenID config that points to our JWKS server
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := OpenIDConfiguration{
			JWKSURI: server.URL,
		}
		json.NewEncoder(w).Encode(config)
	}))
	defer configServer.Close()

	tpp := &TPP{
		directoryIssuer:     configServer.URL,
		directoryMTLSClient: &http.Client{},
	}

	jwks, err := tpp.directoryJWKS()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID != "test-key-id" {
		t.Errorf("Expected key ID 'test-key-id', got %s", jwks.Keys[0].KeyID)
	}
}

func TestDirectoryJWKS_Cache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		jwksResponse := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"alg": "PS256",
					"use": "sig",
					"n":   "test-modulus",
					"e":   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := OpenIDConfiguration{
			Issuer:        "https://directory.example.com",
			AuthEndpoint:  "https://directory.example.com/auth",
			JWKSURI:       server.URL,
			TokenEndpoint: "https://directory.example.com/token",
		}
		json.NewEncoder(w).Encode(config)
	}))
	defer configServer.Close()

	tpp := &TPP{
		directoryIssuer:     configServer.URL,
		directoryMTLSClient: &http.Client{},
	}

	// First call should hit the server
	_, err := tpp.directoryJWKS()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Second call should use cache
	_, err = tpp.directoryJWKS()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Should only have called the server once due to caching
	if callCount != 1 {
		t.Errorf("Expected server to be called once, got %d times", callCount)
	}
}

func TestDirectoryAuthURL(t *testing.T) {
	// Create a test server for the PAR endpoint
	parServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"request_uri": "urn:ietf:params:oauth:request_uri:random-request-uri",
			"expires_in":  300,
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}))
	defer parServer.Close()

	// Create a test server for the OpenID config
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := OpenIDConfiguration{
			Issuer:        "https://directory.example.com",
			AuthEndpoint:  "https://directory.example.com/auth",
			JWKSURI:       "https://directory.example.com/jwks",
			TokenEndpoint: "https://directory.example.com/token",
			MTLS: struct {
				PushedAuthEndpoint   string `json:"pushed_authorization_request_endpoint"`
				TokenEndpoint        string `json:"token_endpoint"`
				RegistrationEndpoint string `json:"registration_endpoint"`
			}{
				PushedAuthEndpoint: parServer.URL,
			},
		}
		json.NewEncoder(w).Encode(config)
	}))
	defer configServer.Close()

	// Generate a test key for JWT signing
	testKey := generateTestKey(t)

	tpp := &TPP{
		directoryIssuer:      configServer.URL,
		softwareID:           "test-software",
		directoryRedirectURI: "https://redirect.example.com",
		directoryMTLSClient:  &http.Client{},
		jwtSignerID:          "test-signer-id",
		jwtSigner:            testKey,
	}

	authURL, codeVerifier, err := tpp.directoryAuthURL(context.Background(), "openid profile")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if authURL == "" {
		t.Error("Expected auth URL to be non-empty")
	}
	if codeVerifier == "" {
		t.Error("Expected code verifier to be non-empty")
	}

	parsedAuthURL, err := url.Parse(authURL)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify the auth URL contains expected parameters
	if parsedAuthURL.Query().Get("client_id") != "test-software" {
		t.Error("Expected auth URL to contain client_id parameter")
	}
	if parsedAuthURL.Query().Get("request_uri") != "urn:ietf:params:oauth:request_uri:random-request-uri" {
		t.Error("Expected auth URL to contain request_uri parameter")
	}
	if parsedAuthURL.Query().Get("response_type") != "code" {
		t.Error("Expected auth URL to contain response_type parameter")
	}
	if parsedAuthURL.Query().Get("scope") != "openid profile" {
		t.Error("Expected auth URL to contain scope parameter")
	}
	if parsedAuthURL.Query().Get("redirect_uri") != "https://redirect.example.com" {
		t.Error("Expected auth URL to contain redirect_uri parameter")
	}
}

func TestDirectoryToken(t *testing.T) {
	// Create a test server for the token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := tokenResponse{
			Token: "test-access-token",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	// Create a test server for the OpenID config
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := OpenIDConfiguration{
			Issuer:        "https://directory.example.com",
			AuthEndpoint:  "https://directory.example.com/auth",
			JWKSURI:       "https://directory.example.com/jwks",
			TokenEndpoint: "https://directory.example.com/token",
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
	defer configServer.Close()

	tpp := &TPP{
		directoryIssuer:      configServer.URL,
		softwareID:           "test-software",
		directoryRedirectURI: "https://redirect.example.com",
		directoryMTLSClient:  &http.Client{},
		jwtSignerID:          "test-signer-id",
		jwtSigner:            generateTestKey(t),
	}

	token, err := tpp.directoryAuthCodeToken(context.Background(), "test-auth-code", "test-code-verifier")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if token.Token != "test-access-token" {
		t.Error("Expected token to be non-empty")
	}
}

func TestDirectoryIDToken(t *testing.T) {
	directoryIssuer := ""
	directoryKey := generateTestKey(t)
	tppKey := generateTestKey(t)

	// Create a test server for JWKS that returns the directory's public key
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create JWKS with directory's public key
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       &directoryKey.PublicKey,
					KeyID:     "signer",
					Algorithm: "PS256",
					Use:       "sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	// Create a test server for the token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		idTokenClaims := map[string]any{
			"iss": directoryIssuer,
			"sub": "test-user",
			"aud": []string{"test-software"},
			"iat": jwt.NewNumericDate(now),
			"exp": jwt.NewNumericDate(now.Add(time.Hour)),
			"nbf": jwt.NewNumericDate(now),
		}

		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.PS256,
			Key:       directoryKey,
		}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "signer"))
		if err != nil {
			t.Fatalf("Failed to create signer: %v", err)
		}

		idToken, err := jwt.Signed(signer).Claims(idTokenClaims).Serialize()
		if err != nil {
			t.Fatalf("Failed to create ID token: %v", err)
		}

		response := tokenResponse{
			IDToken: idToken,
			Token:   "test-access-token",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	// Create a test server for the OpenID config
	configServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := OpenIDConfiguration{
			Issuer:         directoryIssuer,
			AuthEndpoint:   directoryIssuer + "/auth",
			JWKSURI:        jwksServer.URL,
			TokenEndpoint:  directoryIssuer + "/token",
			IDTokenSigAlgs: []jose.SignatureAlgorithm{jose.PS256},
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
	defer configServer.Close()
	directoryIssuer = configServer.URL

	// Create a signed response JWT containing the auth code
	now := time.Now()
	responseClaims := map[string]any{
		"iss":  directoryIssuer,
		"code": "test-auth-code",
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"nbf":  now.Unix(),
	}

	responseSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.PS256,
		Key:       directoryKey,
	}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "signer"))
	if err != nil {
		t.Fatalf("Failed to create response signer: %v", err)
	}

	signedResponse, err := jwt.Signed(responseSigner).Claims(responseClaims).Serialize()
	if err != nil {
		t.Fatalf("Failed to create signed response: %v", err)
	}

	tpp := &TPP{
		directoryIssuer:      directoryIssuer,
		softwareID:           "test-software",
		directoryRedirectURI: "https://redirect.example.com",
		directoryMTLSClient:  &http.Client{},
		jwtSignerID:          "test-signer-id",
		jwtSigner:            tppKey,
	}

	idToken, err := tpp.directoryIDToken(context.Background(), signedResponse, "test-code-verifier")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if idToken.Sub == "" {
		t.Error("Expected ID token to have a subject")
	}
}
