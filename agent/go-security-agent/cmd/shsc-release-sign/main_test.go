package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignAndVerifyRejectsTamperingAndOtherKeys(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "release.key"), filepath.Join(dir, "release.pub")
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("abc  shsc-agent-linux-amd64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", priv, pub}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", priv, pub}); err == nil {
		t.Fatal("keygen must not overwrite an existing private key")
	}
	if err := run([]string{"sign", priv, sums}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", pub, sums}); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// tampered manifest
	if err := os.WriteFile(sums, []byte("abd  shsc-agent-linux-amd64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", pub, sums}); err == nil {
		t.Fatal("tampered file accepted")
	}
	// another key
	other := filepath.Join(dir, "other")
	if err := run([]string{"keygen", other + ".key", other + ".pub"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", priv, sums}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", other + ".pub", sums}); err == nil {
		t.Fatal("signature verified with another public key")
	}
	if err := run([]string{"verify", pub, sums, filepath.Join(dir, "missing.sig")}); err == nil {
		t.Fatal("missing signature accepted")
	}
}
