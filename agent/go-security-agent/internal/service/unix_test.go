//go:build linux || darwin

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckExecutableRefusesHomeDirectoriesAndWritableFiles(t *testing.T) {
	if err := checkExecutable("relative/shsc-agent"); err == nil {
		t.Error("relative path accepted")
	}
	if err := checkExecutable("/home/user/shsc-agent"); err == nil || !strings.Contains(err.Error(), "outside home") {
		t.Errorf("home directory accepted: %v", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("ownership checks need root (the container test run is root)")
	}
	dir := t.TempDir() // under /tmp: world-writable (sticky) parent → must be refused
	bin := filepath.Join(dir, "shsc-agent")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutable(bin); err == nil {
		t.Error("binary below a world-writable directory accepted")
	}
	safeDir, err := os.MkdirTemp("/usr/local", "shsc-test-")
	if err != nil {
		t.Skip("cannot create a directory under /usr/local:", err)
	}
	defer os.RemoveAll(safeDir)
	os.Chmod(safeDir, 0o755)
	safe := filepath.Join(safeDir, "shsc-agent")
	if err := os.WriteFile(safe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutable(safe); err != nil {
		t.Errorf("root-owned 0755 binary refused: %v", err)
	}
	os.Chmod(safe, 0o777)
	if err := checkExecutable(safe); err == nil {
		t.Error("world-writable binary accepted")
	}
}
