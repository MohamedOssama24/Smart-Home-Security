// Package assertion builds the signed proofs the agent presents to the backend
// (private_key_jwt style, RFC 7523): a compact JWS signed with the agent Ed25519 key,
// short lived and with a unique jti so it cannot be replayed.
package assertion

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Audiences accepted by the backend.
const (
	AudienceToken  = "shsc-agent-token"
	AudienceRotate = "shsc-agent-rotate"
)

// MaxLifetime is the longest validity accepted by the backend.
const MaxLifetime = 60 * time.Second

type claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	ID       string `json:"jti"`
}

// Sign returns a compact JWS ("EdDSA") asserting the agent identity for the audience.
func Sign(key ed25519.PrivateKey, agentID, audience string, now time.Time, lifetime time.Duration) (string, error) {
	if agentID == "" || audience == "" {
		return "", errors.New("assertion: agent id and audience are required")
	}
	if lifetime <= 0 || lifetime > MaxLifetime {
		lifetime = MaxLifetime
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims{
		Issuer:   agentID,
		Subject:  agentID,
		Audience: audience,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(lifetime).Unix(),
		ID:       hex.EncodeToString(nonce),
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	signature := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + enc.EncodeToString(signature), nil
}
