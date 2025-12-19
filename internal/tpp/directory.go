package tpp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/raidiam/mock-tpp/internal/jwtutil"
)

const (
	cacheTime = 15 * time.Minute
)

func (t *TPP) directoryAuthURL(ctx context.Context, scopes string) (uri, codeVerifier string, err error) {
	codeVerifier, codeChallenge := generateCodeVerifierAndChallenge()
	reqURI, err := t.directoryRequestURI(ctx, scopes, codeChallenge)
	if err != nil {
		return "", "", err
	}

	openIDConfig, err := t.directoryOpenIDConfig()
	if err != nil {
		return "", "", err
	}

	authURL, _ := url.Parse(openIDConfig.AuthEndpoint)
	query := authURL.Query()
	query.Set("client_id", t.softwareID)
	query.Set("request_uri", reqURI)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("redirect_uri", t.directoryRedirectURI)
	authURL.RawQuery = query.Encode()
	return authURL.String(), codeVerifier, nil
}

func (t *TPP) directoryEndSessionURL() (uri string, err error) {
	openIDConfig, err := t.directoryOpenIDConfig()
	if err != nil {
		return "", err
	}

	authURL, _ := url.Parse(openIDConfig.EndSessionEndpoint)
	query := authURL.Query()
	query.Set("client_id", t.softwareID)
	query.Set("post_logout_redirect_uri", t.directoryEndSessionURI)
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func (t *TPP) directoryIDToken(ctx context.Context, response, codeVerifier string) (IDToken, error) {
	jws, err := jwt.ParseSigned(response, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		return IDToken{}, fmt.Errorf("failed to parse response: %w", err)
	}

	jwks, err := t.directoryJWKS()
	if err != nil {
		return IDToken{}, fmt.Errorf("failed to fetch jwks for verifying response: %w", err)
	}

	var claims map[string]any
	if err := jws.Claims(jwks, &claims); err != nil {
		return IDToken{}, fmt.Errorf("failed to parse response: %w", err)
	}

	if errCode := claims["error"]; errCode != nil {
		return IDToken{}, fmt.Errorf("error granting access: %v %v", errCode, claims["error_description"])
	}

	code := claims["code"]
	if code == nil {
		return IDToken{}, errors.New("authorization code is missing in the response object")
	}

	tokenResp, err := t.directoryAuthCodeToken(ctx, code.(string), codeVerifier)
	if err != nil {
		return IDToken{}, err
	}

	openIDConfig, err := t.directoryOpenIDConfig()
	if err != nil {
		return IDToken{}, fmt.Errorf("failed to fetch the directory openid config for decoding id token: %w", err)
	}

	parsedIDTkn, err := jwt.ParseSigned(tokenResp.IDToken, openIDConfig.IDTokenSigAlgs)
	if err != nil {
		return IDToken{}, fmt.Errorf("failed to parse id token: %w", err)
	}

	var idToken IDToken
	var idTokenClaims jwt.Claims
	if err := parsedIDTkn.Claims(jwks, &idToken, &idTokenClaims); err != nil {
		return IDToken{}, fmt.Errorf("invalid id token signature: %w", err)
	}

	if idTokenClaims.IssuedAt == nil {
		return IDToken{}, errors.New("id token iat claim is missing")
	}

	if idTokenClaims.Expiry == nil {
		return IDToken{}, errors.New("id token exp claim is missing")
	}

	if err := idTokenClaims.Validate(jwt.Expected{
		Issuer:      t.directoryIssuer,
		AnyAudience: []string{t.softwareID},
	}); err != nil {
		return IDToken{}, fmt.Errorf("invalid id token claims: %w", err)
	}

	return idToken, nil
}

func (t *TPP) directoryAuthCodeToken(ctx context.Context, authCode, codeVerifier string) (tokenResponse, error) {
	openIDConfig, err := t.directoryOpenIDConfig()
	if err != nil {
		return tokenResponse{}, fmt.Errorf("failed to fetch the directory openid config for requesting an id token: %w", err)
	}

	form := url.Values{}
	form.Set("client_id", t.softwareID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode)
	form.Set("redirect_uri", t.directoryRedirectURI)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openIDConfig.MTLS.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("error creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.directoryMTLSClient.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		slog.DebugContext(ctx, "error calling the token endpoint", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return tokenResponse{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return tokenResponse{}, fmt.Errorf("error decoding token response: %w", err)
	}

	return result, nil
}

func (t *TPP) directoryRequestURI(ctx context.Context, scopes, codeChallenge string) (string, error) {
	config, err := t.directoryOpenIDConfig()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	reqClaims := map[string]any{
		"iss":                   t.softwareID,
		"response_type":         "code",
		"response_mode":         "jwt",
		"nonce":                 uuid.NewString(),
		"client_id":             t.softwareID,
		"aud":                   config.Issuer,
		"scope":                 scopes,
		"redirect_uri":          t.directoryRedirectURI,
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
		"state":                 uuid.NewString(),
		"iat":                   now,
		"exp":                   now + 300,
		"nbf":                   now,
		"jti":                   uuid.NewString(),
	}
	reqObject, err := jwtutil.Sign(reqClaims, t.jwtSignerID, t.jwtSigner)
	if err != nil {
		return "", fmt.Errorf("could not sign the request object: %w", err)
	}

	form := url.Values{}
	form.Set("client_id", t.softwareID)
	form.Set("request", reqObject)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.MTLS.PushedAuthEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating par request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.directoryMTLSClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("par request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		slog.DebugContext(ctx, "error calling the par endpoint", "status_code", resp.StatusCode, "body", string(bodyBytes))
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

func (t *TPP) directoryOpenIDConfig() (OpenIDConfiguration, error) {

	t.directoryOpenidConfigMu.Lock()
	defer t.directoryOpenidConfigMu.Unlock()

	if t.directoryOpenidConfigCache != nil && time.Now().Before(t.directoryOpenidConfigLastFetchedAt.Add(cacheTime)) {
		return *t.directoryOpenidConfigCache, nil
	}

	resp, err := http.Get(t.directoryIssuer + "/.well-known/openid-configuration")
	if err != nil {
		return OpenIDConfiguration{}, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return OpenIDConfiguration{}, fmt.Errorf("directory openid config unexpected status code: %d", resp.StatusCode)
	}

	var config OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return OpenIDConfiguration{}, fmt.Errorf("failed to decode directory openid config response: %w", err)
	}

	t.directoryOpenidConfigCache = &config
	t.directoryOpenidConfigLastFetchedAt = time.Now()
	return config, nil
}

func (t *TPP) directoryJWKS() (jose.JSONWebKeySet, error) {

	t.directoryJWKSMu.Lock()
	defer t.directoryJWKSMu.Unlock()

	if t.directoryJWKSCache != nil && time.Now().Before(t.directoryJWKSLastFetchedAt.Add(cacheTime)) {
		return *t.directoryJWKSCache, nil
	}

	openIDConfig, err := t.directoryOpenIDConfig()
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}

	resp, err := http.Get(openIDConfig.JWKSURI)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("directory openid config jwks unexpected status code: %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("failed to decode directory jwks response: %w", err)
	}

	t.directoryJWKSCache = &jwks
	t.directoryJWKSLastFetchedAt = time.Now()
	return jwks, nil
}

func (t *TPP) directorySoftwareStatement(ctx context.Context) (string, error) {
	token, err := t.directoryClientCredentialsToken(ctx, "directory:software")
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.directorySoftwareStatementURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating software statement request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := t.directoryMTLSClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	ssa, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading software statement response: %w", err)
	}

	return string(ssa), nil
}

func (t *TPP) directoryClientCredentialsToken(ctx context.Context, scopes string) (string, error) {
	config, err := t.directoryOpenIDConfig()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("client_id", t.softwareID)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", scopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.MTLS.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.directoryMTLSClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.DebugContext(ctx, "token request failed", "status", resp.Status, "body", string(body))
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
