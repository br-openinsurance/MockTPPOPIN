package tpp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/br-openinsurance/MockTPPOPIN/internal/jwtutil"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

func (t *TPP) AuthServer(ctx context.Context, id, orgID string) (AuthServer, error) {
	participant, err := t.participant(ctx, orgID)
	if err != nil {
		return AuthServer{}, err
	}

	for _, authServer := range participant.AuthServers {
		if authServer.ID == id {
			return authServer, nil
		}
	}
	return AuthServer{}, fmt.Errorf("auth server not found: %s", id)
}

func (t *TPP) Participants(_ context.Context, orgIDs []string) ([]Participant, error) {
	participants, err := t.participants()
	if err != nil {
		return nil, err
	}

	filteredParticipants := make([]Participant, 0)
	for _, participant := range participants {
		if slices.Contains(orgIDs, participant.OrgID) {
			filteredParticipants = append(filteredParticipants, participant)
		}
	}
	return filteredParticipants, nil
}

func (t *TPP) participant(ctx context.Context, orgID string) (Participant, error) {
	participants, err := t.Participants(ctx, []string{orgID})
	if err != nil {
		return Participant{}, err
	}

	if len(participants) == 0 {
		return Participant{}, fmt.Errorf("participant not found: %s", orgID)
	}

	return participants[0], nil
}

func (t *TPP) participants() ([]Participant, error) {
	t.participantsCacheMu.Lock()
	defer t.participantsCacheMu.Unlock()

	if time.Since(t.participantsLastFetchedAt) < 15*time.Minute {
		return t.participantsCache, nil
	}

	resp, err := http.Get(t.participantsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var participants []Participant
	if err := json.NewDecoder(resp.Body).Decode(&participants); err != nil {
		return nil, fmt.Errorf("failed to decode participants response: %w", err)
	}

	t.participantsCache = participants
	t.participantsLastFetchedAt = time.Now().UTC()

	return participants, nil
}

func (t *TPP) participantAuthURL(ctx context.Context, flow *Flow, consentID string) (uri, codeVerifier string, err error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return "", "", err
	}

	config, err := t.participantOpenIDConfig(ctx, authServer.OpenIDConfigURL)
	if err != nil {
		return "", "", err
	}

	scopes := strings.Join([]string{"openid", "consent:" + consentID, flow.APIType.Scope()}, " ")
	codeVerifier, codeChallenge := generateCodeVerifierAndChallenge()

	reqURI, err := t.participantRequestURI(ctx, flow, config, scopes, codeChallenge, flow.ID)
	if err != nil {
		return "", "", err
	}

	authURL, _ := url.Parse(config.AuthEndpoint)
	query := authURL.Query()
	query.Set("client_id", flow.ClientID)
	query.Set("request_uri", reqURI)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("redirect_uri", t.participantRedirectURI)
	query.Set("state", flow.ID)
	authURL.RawQuery = encodeQuery(query)
	return authURL.String(), codeVerifier, nil
}

func (t *TPP) ParticipantDCR(ctx context.Context, authServer AuthServer) error {
	client, err := t.client(ctx, authServer.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	if client != nil {
		return nil
	}

	openIDConfig, err := t.participantOpenIDConfig(ctx, authServer.OpenIDConfigURL)
	if err != nil {
		return err
	}

	ssa, err := t.directorySoftwareStatement(ctx)
	if err != nil {
		return err
	}

	payload := map[string]any{
		"grant_types":                []string{"authorization_code", "implicit", "refresh_token", "client_credentials"},
		"jwks_uri":                   t.keystoreURL + "/" + t.orgID + "/" + t.softwareID + "/application.jwks",
		"token_endpoint_auth_method": "private_key_jwt",
		"response_types":             []string{"code", "code id_token"},
		"redirect_uris":              []string{t.participantRedirectURI},
		"software_statement":         ssa,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openIDConfig.MTLS.RegistrationEndpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		slog.DebugContext(ctx, "participant dcr request failed", "status", resp.Status, "request", payload, "response", string(body))
		return fmt.Errorf("participant dcr request failed: %s %s", resp.Status, string(body))
	}

	var result struct {
		ClientID                string `json:"client_id"`
		RegistrationAccessToken string `json:"registration_access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("error decoding participant client id response: %w", err)
	}

	return t.saveClient(ctx, &Client{
		AuthServerID:      authServer.ID,
		ClientID:          result.ClientID,
		RegistrationToken: result.RegistrationAccessToken,
		CreatedAt:         timestampNow(),
	})
}

func (t *TPP) participantRequestURI(ctx context.Context, flow *Flow, config OpenIDConfiguration, scopes, codeChallenge, state string) (string, error) {
	assertion, err := t.participantClientAssertion(config, flow.ClientID)
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	reqClaims := map[string]any{
		"iss":                   flow.ClientID,
		"response_type":         "code",
		"response_mode":         "jwt",
		"nonce":                 uuid.NewString(),
		"client_id":             flow.ClientID,
		"aud":                   config.Issuer,
		"scope":                 scopes,
		"redirect_uri":          t.participantRedirectURI,
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
		"state":                 state,
		"iat":                   now,
		"exp":                   now + 300,
		"nbf":                   now,
		"jti":                   uuid.NewString(),
	}
	t.Info(ctx, flow.ID, "creating request object", slog.Any("request_claims", reqClaims))
	reqObject, err := jwtutil.Sign(reqClaims, t.jwtSignerID, t.jwtSigner)
	if err != nil {
		return "", fmt.Errorf("could not sign the request object: %w", err)
	}

	form := url.Values{}
	form.Set("client_id", flow.ClientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("request", reqObject)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.MTLS.PushedAuthEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating par request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("par request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Error(ctx, flow.ID, "participant par request failed", slog.String("status", resp.Status), slog.String("body", string(body)))
		return "", fmt.Errorf("par endpoint returned status %d", resp.StatusCode)
	}

	var result struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding par response: %w", err)
	}

	return result.RequestURI, nil
}

func (t *TPP) participantClientCredentialsToken(ctx context.Context, flow *Flow, authServer AuthServer, scopes string) (string, error) {
	config, err := t.participantOpenIDConfig(ctx, authServer.OpenIDConfigURL)
	if err != nil {
		return "", err
	}

	assertion, err := t.participantClientAssertion(config, flow.ClientID)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("client_id", flow.ClientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", scopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.MTLS.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Error(ctx, flow.ID, "token request failed", slog.String("status", resp.Status), slog.String("body", string(body)))
		return "", fmt.Errorf("token request failed: %s", resp.Status)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding token response: %w", err)
	}

	return result.AccessToken, nil
}

func (t *TPP) participantClientAssertion(config OpenIDConfiguration, clientID string) (string, error) {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": config.TokenEndpoint,
		"jti": uuid.NewString(),
		"iat": now,
		"exp": now + 300,
		"nbf": now,
	}

	assertion, err := jwtutil.Sign(claims, t.jwtSignerID, t.jwtSigner)
	if err != nil {
		return "", fmt.Errorf("could not sign the client assertion: %w", err)
	}

	return assertion, nil
}

func (t *TPP) participantOpenIDConfig(ctx context.Context, openidConfigURL string) (OpenIDConfiguration, error) {
	config, err := openIDConfig(ctx, openidConfigURL)
	if err != nil {
		return OpenIDConfiguration{}, fmt.Errorf("failed to fetch participant openid config: %w", err)
	}

	return config, nil
}

func (t *TPP) participantAuthCodeToken(ctx context.Context, flow *Flow, authServer AuthServer, authCode string) (tokenResponse, error) {
	openIDConfig, err := t.participantOpenIDConfig(ctx, authServer.OpenIDConfigURL)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("failed to fetch the participant openid config for requesting an id token: %w", err)
	}

	assertion, err := t.participantClientAssertion(openIDConfig, flow.ClientID)
	if err != nil {
		return tokenResponse{}, err
	}

	form := url.Values{}
	form.Set("client_id", flow.ClientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode)
	form.Set("redirect_uri", t.participantRedirectURI)
	form.Set("code_verifier", flow.CodeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openIDConfig.MTLS.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("error creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Error(ctx, flow.ID, "error calling the token endpoint", slog.String("status_code", resp.Status), slog.String("body", string(bodyBytes)))
		return tokenResponse{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return tokenResponse{}, fmt.Errorf("error decoding token response: %w", err)
	}

	return result, nil
}

func (t *TPP) participantJWKS(ctx context.Context, authServer AuthServer) (jose.JSONWebKeySet, error) {

	openIDConfig, err := t.participantOpenIDConfig(ctx, authServer.OpenIDConfigURL)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("failed to fetch the participant openid config for requesting a jwks: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openIDConfig.JWKSURI, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("failed to create request for fetching participant jwks: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("failed to fetch participant jwks: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("fetching participant jwks resulted in unexpected status code: %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("failed to decode participant jwks response: %w", err)
	}

	return jwks, nil
}
