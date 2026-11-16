package agentauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"shsc/agent/internal/assertion"
	"shsc/agent/internal/cloud"
	"shsc/agent/internal/identity"
)

// fakeBackend is a TEST DOUBLE of the agent API: it applies the same checks as the real
// backend (one-time token, Ed25519 signature, audience, lifetime, jti replay) so that the
// client protocol is verified end to end over real TLS. The real backend is covered by
// AgentAuthenticationTest (Java) and by the manual end-to-end check in PROJECT_STATUS.md.
type fakeBackend struct {
	mu        sync.Mutex
	token     string
	tokenUsed bool
	key       ed25519.PublicKey
	seenJTI   map[string]bool
	access    map[string]bool
	revoked   bool
}

func newFakeBackend(t *testing.T) (*fakeBackend, *httptest.Server, string) {
	t.Helper()
	fb := &fakeBackend{token: "shsc_enr_valid", seenJTI: map[string]bool{}, access: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/enroll", fb.enroll)
	mux.HandleFunc("POST /api/v1/agent/token", fb.issue)
	mux.HandleFunc("GET /api/v1/agent/session", fb.session)
	mux.HandleFunc("POST /api/v1/agent/credentials/rotate", fb.rotate)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return fb, srv, caFile
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "detail": code})
}

func (fb *fakeBackend) enroll(w http.ResponseWriter, r *http.Request) {
	var req cloud.EnrollRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if req.EnrollmentToken != fb.token || fb.tokenUsed {
		problem(w, 401, "INVALID_ENROLLMENT_TOKEN")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize || req.OS == "" || req.AgentVersion == "" {
		problem(w, 400, "INVALID_PUBLIC_KEY")
		return
	}
	fb.tokenUsed = true
	fb.key = raw
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(cloud.EnrollResponse{AgentID: "agent-1", HomeID: "home-1", CredentialID: "cred-1"})
}

// verify checks a compact JWS like the backend does and returns the jti.
func verify(token string, key ed25519.PublicKey, audience string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || key == nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return "", false
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp           int64
	}
	if json.Unmarshal(payload, &c) != nil {
		return "", false
	}
	now := time.Now().Unix()
	ok := c.Iss == "agent-1" && c.Sub == "agent-1" && c.Aud == audience && c.Exp-c.Iat <= 60 &&
		c.Exp >= now-30 && c.Iat <= now+30 && len(c.Jti) >= 16
	return c.Jti, ok
}

func (fb *fakeBackend) issue(w http.ResponseWriter, r *http.Request) {
	var req struct{ Assertion string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.revoked {
		problem(w, 401, "AGENT_REVOKED")
		return
	}
	jti, ok := verify(req.Assertion, fb.key, assertion.AudienceToken)
	if !ok || fb.seenJTI[jti] {
		problem(w, 401, "INVALID_AGENT_ASSERTION")
		return
	}
	fb.seenJTI[jti] = true
	token := "shsc_at_" + jti
	fb.access[token] = true
	_ = json.NewEncoder(w).Encode(cloud.TokenResponse{AccessToken: token, TokenType: "Bearer", ExpiresIn: 600,
		ExpiresAt: time.Now().Add(10 * time.Minute)})
}

func (fb *fakeBackend) authorized(r *http.Request) bool {
	return fb.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
}

func (fb *fakeBackend) session(w http.ResponseWriter, r *http.Request) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if !fb.authorized(r) {
		problem(w, 401, "INVALID_AGENT_TOKEN")
		return
	}
	_ = json.NewEncoder(w).Encode(cloud.SessionResponse{AgentID: "agent-1", HomeID: "home-1", HomeName: "Casa",
		CredentialID: "cred-1", TokenExpiresAt: time.Now().Add(10 * time.Minute)})
}

func (fb *fakeBackend) rotate(w http.ResponseWriter, r *http.Request) {
	var req struct{ PublicKey, Proof string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if !fb.authorized(r) {
		problem(w, 401, "INVALID_AGENT_TOKEN")
		return
	}
	next, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil {
		problem(w, 400, "INVALID_ROTATION")
		return
	}
	if _, ok := verify(req.Proof, next, assertion.AudienceRotate); !ok {
		problem(w, 400, "INVALID_ROTATION")
		return
	}
	fb.key = next
	fb.access = map[string]bool{}
	_ = json.NewEncoder(w).Encode(cloud.RotateResponse{CredentialID: "cred-2"})
}

func (fb *fakeBackend) publicKey() ed25519.PublicKey {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return fb.key
}

func enrolled(t *testing.T) (*fakeBackend, Service, identity.Store) {
	t.Helper()
	fb, srv, ca := newFakeBackend(t)
	store := identity.Store{Dir: filepath.Join(t.TempDir(), "state")}
	svc := Service{Store: store}
	if _, err := svc.Enroll(context.Background(), srv.URL, ca, "shsc_enr_valid", "pc"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return fb, svc, store
}

func TestEnrollStoresIdentityAndPrivateKeyLocally(t *testing.T) {
	fb, _, store := enrolled(t)
	state, key, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.AgentID != "agent-1" || state.HomeID != "home-1" || state.CredentialID != "cred-1" {
		t.Errorf("unexpected state %+v", state)
	}
	if !key.Public().(ed25519.PublicKey).Equal(fb.publicKey()) {
		t.Error("the backend received a public key that does not match the stored private key")
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"agent.json", "agent.key"} {
			info, err := os.Stat(filepath.Join(store.Dir, name))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("%s must be 0600, got %v (%v)", name, info.Mode().Perm(), err)
			}
		}
	}
}

func TestEnrollRejectsHTTPAndReuse(t *testing.T) {
	_, srv, ca := newFakeBackend(t)
	svc := Service{Store: identity.Store{Dir: t.TempDir()}}
	plain := strings.Replace(srv.URL, "https://", "http://", 1)
	if _, err := svc.Enroll(context.Background(), plain, ca, "shsc_enr_valid", ""); err == nil ||
		!strings.Contains(err.Error(), "https") {
		t.Fatalf("plain HTTP must be refused, got %v", err)
	}
	if _, err := svc.Enroll(context.Background(), srv.URL, ca, "shsc_enr_wrong", ""); !cloud.IsCode(err, "INVALID_ENROLLMENT_TOKEN") {
		t.Fatalf("expected INVALID_ENROLLMENT_TOKEN, got %v", err)
	}
	if svc.Store.Exists() {
		t.Fatal("no identity must be stored after a failed enrollment")
	}
}

func TestEnrollRefusesUntrustedCertificate(t *testing.T) {
	_, srv, _ := newFakeBackend(t)
	svc := Service{Store: identity.Store{Dir: t.TempDir()}}
	if _, err := svc.Enroll(context.Background(), srv.URL, "", "shsc_enr_valid", ""); err == nil {
		t.Fatal("a certificate not signed by a trusted CA must be refused")
	}
}

func TestEnrollingTwiceIsRefused(t *testing.T) {
	_, svc, _ := enrolled(t)
	if _, err := svc.Enroll(context.Background(), "https://example.invalid", "", "x", ""); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("expected ErrAlreadyEnrolled, got %v", err)
	}
}

func TestCheckAuthenticatesWithSignedAssertion(t *testing.T) {
	_, svc, _ := enrolled(t)
	info, err := svc.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.HomeName != "Casa" {
		t.Errorf("unexpected session %+v", info)
	}
}

func TestRevokedAgentGetsAClearError(t *testing.T) {
	fb, svc, _ := enrolled(t)
	fb.mu.Lock()
	fb.revoked = true
	fb.mu.Unlock()
	if _, err := svc.Check(context.Background()); !cloud.IsCode(err, "AGENT_REVOKED") {
		t.Fatalf("expected AGENT_REVOKED, got %v", err)
	}
}

func TestRotateKeyReplacesTheKey(t *testing.T) {
	fb, svc, store := enrolled(t)
	_, oldKey, _ := store.Load()

	credential, err := svc.RotateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state, newKey, _ := store.Load()
	if credential != "cred-2" || state.CredentialID != "cred-2" {
		t.Errorf("credential not updated: %s / %+v", credential, state)
	}
	if newKey.Equal(oldKey) || !newKey.Public().(ed25519.PublicKey).Equal(fb.publicKey()) {
		t.Fatal("the stored key is not the one accepted by the backend")
	}
	if _, pending, _ := store.PendingKey(); pending {
		t.Error("pending key must be promoted")
	}
	if _, err := svc.Check(context.Background()); err != nil {
		t.Fatalf("login with the new key: %v", err)
	}
}

func TestInterruptedRotationIsRecoveredAtNextLogin(t *testing.T) {
	fb, svc, store := enrolled(t)
	// the backend accepted a new key but the agent crashed before promoting it
	next, _ := identity.GenerateKey()
	if err := store.SavePendingKey(next); err != nil {
		t.Fatal(err)
	}
	fb.mu.Lock()
	fb.key = next.Public().(ed25519.PublicKey)
	fb.mu.Unlock()

	if _, err := svc.Check(context.Background()); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	_, current, _ := store.Load()
	if !current.Equal(next) {
		t.Fatal("the pending key was not promoted")
	}
}
