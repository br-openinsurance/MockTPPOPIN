package jwtutil

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestSign(t *testing.T) {
	// Given.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signerID := "test-signer-123"

	claims := map[string]any{
		"sub": "test-subject",
		"iss": "test-issuer",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	// When.
	token, err := Sign(claims, signerID, privateKey)

	// Then.
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if token == "" {
		t.Error("token cannot be empty")
		return
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Errorf("Failed to parse signed token: %v", err)
		return
	}

	var verifiedClaims jwt.Claims
	err = parsed.Claims(privateKey.Public(), &verifiedClaims)
	if err != nil {
		t.Errorf("Failed to verify token signature: %v", err)
		return
	}
}
