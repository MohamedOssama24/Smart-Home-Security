package cli

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shsc/agent/internal/identity"
)

func TestHelpListsTheServiceCommands(t *testing.T) {
	_, stdout, _ := run("help")
	for _, cmd := range []string{"run ", "service ", "diagnose "} {
		if !strings.Contains(stdout, "\n  "+cmd) {
			t.Errorf("help does not list %q", cmd)
		}
	}
}

func TestRunWithoutIdentityExitsWithoutRestart(t *testing.T) {
	code, _, stderr := run("run", "--state-dir", t.TempDir())
	if code != ExitNotEnrolled || !strings.Contains(stderr, "not enrolled") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestServiceCommandValidation(t *testing.T) {
	if code, _, stderr := run("service"); code != ExitUsage || !strings.Contains(stderr, "install|uninstall") {
		t.Fatalf("no action: code=%d", code)
	}
	if code, _, _ := run("service", "explode"); code != ExitUsage {
		t.Fatalf("unknown action: code=%d", code)
	}
	if code, _, stderr := run("service", "install", "--state-dir", t.TempDir()); code != ExitNotEnrolled ||
		!strings.Contains(stderr, "enroll the agent first") {
		t.Fatalf("install before enrollment: code=%d stderr=%q", code, stderr)
	}
}

func TestDiagnoseOfflineJSON(t *testing.T) {
	code, stdout, _ := run("diagnose", "--offline", "--json", "--state-dir", t.TempDir())
	if code != ExitNotEnrolled {
		t.Fatalf("code=%d", code)
	}
	var d diagnosis
	if err := json.Unmarshal([]byte(stdout), &d); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout, err)
	}
	if d.Enrolled || d.Capabilities.ARP == "" || d.Capabilities.ICMP == "" || d.Agent.Version == "" || d.Backend != nil {
		t.Fatalf("unexpected diagnosis %+v", d)
	}
}

func TestDiagnoseTextReportsBackendFailure(t *testing.T) {
	dir := t.TempDir()
	key, _ := identity.GenerateKey()
	// enrolled against an address where nothing listens
	if err := (identity.Store{Dir: dir}).Save(identity.State{AgentID: "a1", HomeID: "h1",
		APIURL: "https://127.0.0.1:1"}, key); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := run("diagnose", "--state-dir", dir)
	if code != ExitError || !strings.Contains(stdout, "Backend:         NOT reachable") ||
		!strings.Contains(stdout, "Enrollment:      enrolled (agent a1") {
		t.Fatalf("code=%d stdout=%s", code, stdout)
	}
}

// A revoked agent started by the service manager stops at once with ExitRevoked and its
// keys are deleted, so it is not restarted.
func TestRunStopsWithExitRevoked(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":401,"code":"AGENT_REVOKED","detail":"revoked"}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	key, _ := identity.GenerateKey()
	if err := (identity.Store{Dir: stateDir}).Save(identity.State{AgentID: "a1", HomeID: "h1", APIURL: srv.URL,
		CAFile: caFile}, key); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run("run", "--state-dir", stateDir, "--log-file", filepath.Join(dir, "agent.log"))
	if code != ExitRevoked || !strings.Contains(stderr, "revoked") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if (identity.Store{Dir: stateDir}).Exists() {
		t.Fatal("identity must be retired")
	}
	logged, _ := os.ReadFile(filepath.Join(dir, "agent.log"))
	if !strings.Contains(string(logged), "agent revoked") || strings.Contains(string(logged), "PRIVATE KEY") {
		t.Fatalf("unexpected log: %s", logged)
	}
}
