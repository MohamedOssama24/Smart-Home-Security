package cli

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"shsc/agent/internal/buildinfo"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestNoArgumentsPrintsUsageAndFails(t *testing.T) {
	code, stdout, stderr := run()
	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, ExitUsage)
	}
	if stdout != "" || !strings.Contains(stderr, "Usage:") {
		t.Fatalf("usage expected on stderr, got stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestHelp(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, stdout, _ := run(arg)
		if code != ExitOK || !strings.Contains(stdout, "Commands:") {
			t.Errorf("%s: code=%d stdout=%q", arg, code, stdout)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, stderr := run("scan")
	if code != ExitUsage || !strings.Contains(stderr, `unknown command "scan"`) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestVersionText(t *testing.T) {
	code, stdout, _ := run("version")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	want := buildinfo.Get().String()
	if strings.TrimSpace(stdout) != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}

func TestVersionJSON(t *testing.T) {
	code, stdout, _ := run("version", "--json")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	var info buildinfo.Info
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout, err)
	}
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH || info.Version == "" {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestVersionRejectsUnknownFlagsAndArgs(t *testing.T) {
	if code, _, _ := run("version", "--yaml"); code != ExitUsage {
		t.Errorf("unknown flag: code = %d", code)
	}
	if code, _, _ := run("version", "extra"); code != ExitUsage {
		t.Errorf("extra arg: code = %d", code)
	}
}

func TestEnrollValidatesFlags(t *testing.T) {
	t.Setenv("SHSC_ENROLLMENT_TOKEN", "")
	dir := t.TempDir()
	if code, _, stderr := run("enroll", "--state-dir", dir, "--token", "x"); code != ExitUsage ||
		!strings.Contains(stderr, "--api is required") {
		t.Fatalf("missing --api: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := run("enroll", "--state-dir", dir, "--api", "https://example.invalid"); code != ExitUsage ||
		!strings.Contains(stderr, "enrollment token is required") {
		t.Fatalf("missing token: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := run("enroll", "--state-dir", dir, "--api", "http://example.invalid", "--token", "x"); code != ExitError ||
		!strings.Contains(stderr, "https") {
		t.Fatalf("plain http: code=%d stderr=%q", code, stderr)
	}
}

func TestStatusWithoutEnrollment(t *testing.T) {
	code, _, stderr := run("status", "--state-dir", t.TempDir())
	if code != ExitError || !strings.Contains(stderr, "not enrolled") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}
