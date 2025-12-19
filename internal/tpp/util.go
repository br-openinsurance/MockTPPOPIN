package tpp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func openIDConfig(ctx context.Context, openidConfigURL string) (OpenIDConfiguration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openidConfigURL, nil)
	if err != nil {
		return OpenIDConfiguration{}, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return OpenIDConfiguration{}, fmt.Errorf("failed to fetch openid config: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return OpenIDConfiguration{}, fmt.Errorf("fetching openid config resulted in unexpected status code: %d", resp.StatusCode)
	}

	var config OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return OpenIDConfiguration{}, fmt.Errorf("failed to decode openid config response: %w", err)
	}

	return config, nil
}

func generateCodeVerifierAndChallenge() (verifier, challenge string) {
	b := make([]byte, 50)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge
}

func encodeQuery(q url.Values) string {
	return strings.ReplaceAll(q.Encode(), "+", "%20")
}

func formatDateTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05Z")
}

func timeNow() time.Time {
	return time.Now().UTC()
}

func timestampNow() int {
	return int(time.Now().Unix())
}

func timestampNowMilli() int {
	return int(time.Now().UnixMilli())
}
