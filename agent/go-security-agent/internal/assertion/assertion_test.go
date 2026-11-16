package assertion

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignProducesAVerifiableShortLivedAssertion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)

	token, err := Sign(priv, "agent-1", AudienceToken, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signature does not verify")
	}

	var header map[string]string
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(raw, &header)
	if header["alg"] != "EdDSA" {
		t.Errorf("alg = %q", header["alg"])
	}

	var c claims
	raw, _ = base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &c)
	if c.Issuer != "agent-1" || c.Subject != "agent-1" || c.Audience != AudienceToken {
		t.Errorf("unexpected claims %+v", c)
	}
	if c.Expiry-c.IssuedAt != int64(MaxLifetime.Seconds()) {
		t.Errorf("lifetime must be capped to %s, got %ds", MaxLifetime, c.Expiry-c.IssuedAt)
	}
	if len(c.ID) != 32 {
		t.Errorf("jti must be 128 random bits, got %q", c.ID)
	}
}

func TestEveryAssertionHasAUniqueID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := Sign(priv, "agent", AudienceToken, time.Now(), time.Minute)
	b, _ := Sign(priv, "agent", AudienceToken, time.Now(), time.Minute)
	if a == b {
		t.Fatal("two assertions are identical: replay protection would reject the second")
	}
}

func TestSignRequiresIdentity(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Sign(priv, "", AudienceToken, time.Now(), time.Minute); err == nil {
		t.Fatal("expected an error without agent id")
	}
}
