package scan

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"shsc/agent/internal/cloud"
)

const testAgent = "0197a000-0000-7000-8000-000000000001"

func testKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.RawURLEncoding.EncodeToString(pub)
}

func jobPayload(mutate func(map[string]any)) map[string]any {
	job := map[string]any{
		"schemaVersion": 1, "scanId": "s1", "agentId": testAgent, "homeId": "h1", "profile": "DISCOVERY",
		"targets":   []map[string]any{{"networkId": "n1", "cidr": "192.168.50.0/24"}},
		"limits":    map[string]any{"maxHosts": 1024, "ratePerSecond": 50, "concurrency": 16, "maxDurationSeconds": 900},
		"issuedAt":  time.Now().UTC().Format(time.RFC3339),
		"expiresAt": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
	}
	if mutate != nil {
		mutate(job)
	}
	return job
}

func sign(t *testing.T, key ed25519.PrivateKey, job map[string]any) cloud.SignedJob {
	t.Helper()
	payload, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	return cloud.SignedJob{Payload: base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))}
}

func TestVerifyAcceptsASignedJobForThisAgent(t *testing.T) {
	priv, pub := testKey(t)
	job, err := Verify(sign(t, priv, jobPayload(nil)), pub, testAgent, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if job.ScanID != "s1" || len(job.Prefixes) != 1 || job.Prefixes[0].String() != "192.168.50.0/24" {
		t.Fatalf("unexpected job %+v", job)
	}
}

func TestVerifyRefusesTamperedOrForeignJobs(t *testing.T) {
	priv, pub := testKey(t)
	other, _ := testKey(t)
	tampered := sign(t, priv, jobPayload(nil))
	payload, _ := base64.RawURLEncoding.DecodeString(tampered.Payload)
	tampered.Payload = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload),
		"192.168.50.0/24", "192.168.60.0/24", 1)))

	cases := map[string]cloud.SignedJob{
		"signed by another key": sign(t, other, jobPayload(nil)),
		"tampered payload":      tampered,
		"another agent":         sign(t, priv, jobPayload(func(j map[string]any) { j["agentId"] = "someone-else" })),
		"expired": sign(t, priv, jobPayload(func(j map[string]any) {
			j["expiresAt"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		})),
		"public target": sign(t, priv, jobPayload(func(j map[string]any) {
			j["targets"] = []map[string]any{{"networkId": "n1", "cidr": "8.8.8.0/24"}}
		})),
		"unknown profile": sign(t, priv, jobPayload(func(j map[string]any) { j["profile"] = "DEEP" })),
		"no targets":      sign(t, priv, jobPayload(func(j map[string]any) { j["targets"] = []any{} })),
		"bad limits": sign(t, priv, jobPayload(func(j map[string]any) {
			j["limits"] = map[string]any{"maxHosts": 0, "ratePerSecond": 50, "concurrency": 16, "maxDurationSeconds": 900}
		})),
	}
	for name, signed := range cases {
		if _, err := Verify(signed, pub, testAgent, time.Now()); err == nil {
			t.Errorf("%s: job accepted", name)
		}
	}
	if _, err := Verify(sign(t, priv, jobPayload(nil)), "", testAgent, time.Now()); err == nil {
		t.Error("job accepted without a pinned key")
	}
}
