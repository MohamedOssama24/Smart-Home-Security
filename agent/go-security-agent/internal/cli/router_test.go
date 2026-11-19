package cli

import (
	"bytes"
	"strings"
	"testing"

	"shsc/agent/internal/identity"
)

func runWithStdin(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	saved := stdin
	t.Cleanup(func() { stdin = saved })
	stdin = strings.NewReader(input)
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRouterSettingsAreStoredLocallyAndNeverPrinted(t *testing.T) {
	dir := t.TempDir()
	const secret = "mock-router-secret-1"
	if code, _, stderr := runWithStdin(t, secret+"\n", "router", "set-tr064", "--address", "192.168.178.1",
		"--username", "owner", "--state-dir", dir); code != ExitOK {
		t.Fatalf("set-tr064: %d %s", code, stderr)
	}
	if code, _, stderr := runWithStdin(t, "mock-community-7\n", "router", "set-snmp", "--address", "192.168.178.1",
		"--version", "2c", "--state-dir", dir); code != ExitOK {
		t.Fatalf("set-snmp: %d %s", code, stderr)
	}
	code, stdout, _ := runWithStdin(t, "", "router", "show", "--state-dir", dir)
	if code != ExitOK || strings.Contains(stdout, secret) || strings.Contains(stdout, "mock-community-7") ||
		!strings.Contains(stdout, "TR-064") || !strings.Contains(stdout, "SNMP v2c") {
		t.Fatalf("show: %d %q", code, stdout)
	}
	if r := detectWithRouter(identity.Store{Dir: dir}); strings.Join(r.RouterIntegrations, ",") != "TR064,SNMP" {
		t.Fatalf("capabilities %v", r.RouterIntegrations)
	}
	if code, _, _ := runWithStdin(t, "", "router", "remove", "--state-dir", dir); code != ExitOK {
		t.Fatal("remove failed")
	}
	if r := detectWithRouter(identity.Store{Dir: dir}); len(r.RouterIntegrations) != 0 {
		t.Fatalf("integrations still reported: %v", r.RouterIntegrations)
	}
}

func TestRouterRefusesDefaultCommunity(t *testing.T) {
	code, _, stderr := runWithStdin(t, "public\n", "router", "set-snmp", "--address", "192.168.1.1", "--version", "2c",
		"--state-dir", t.TempDir())
	if code == ExitOK || !strings.Contains(stderr, "default communities are refused") {
		t.Fatalf("%d %s", code, stderr)
	}
}
