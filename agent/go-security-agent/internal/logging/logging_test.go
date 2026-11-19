package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLogRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	logger, closer, err := File(path)
	if err != nil {
		t.Fatal(err)
	}
	w := closer.(*rotatingFile)
	w.max = 300
	for i := 0; i < 10; i++ {
		logger.Info("heartbeat sent", "attempt", i)
	}
	closer.Close()
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal("rotated file missing:", err)
	}
	if len(current) > 300 || !strings.Contains(string(previous), `"msg":"heartbeat sent"`) {
		t.Fatalf("unexpected rotation: %d bytes current", len(current))
	}
	if !strings.Contains(string(current), `"attempt":9`) {
		t.Fatal("last record must be in the current file")
	}
}
