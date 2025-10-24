package jwtutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func Sign(claims any, signerID string, signer crypto.Signer) (string, error) {
	key := jose.SigningKey{
		Algorithm: jose.PS256,
		Key: opaqueSigner{
			ID:     signerID,
			Signer: signer,
		},
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")

	joseSigner, err := jose.NewSigner(key, opts)
	if err != nil {
		return "", err
	}

	jws, err := jwt.Signed(joseSigner).Claims(claims).Serialize()
	if err != nil {
		return "", err
	}

	return jws, nil
}

var _ jose.OpaqueSigner = opaqueSigner{}

type opaqueSigner struct {
	ID     string
	Signer crypto.Signer
}

func (s opaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		KeyID:     s.ID,
		Key:       s.Signer.Public(),
		Algorithm: string(jose.PS256),
		Use:       "sig",
	}
}

func (s opaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.PS256}
}

func (s opaqueSigner) SignPayload(payload []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	hasher := crypto.SHA256.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	return s.Signer.Sign(rand.Reader, digest, opts)
}
