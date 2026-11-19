package identity

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSaveLoadAndKeyProtection(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "agent")}
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	state := State{AgentID: "a1", HomeID: "h1", CredentialID: "c1", APIURL: "https://example.test"}
	if err := store.Save(state, key); err != nil {
		t.Fatal(err)
	}
	loaded, loadedKey, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgentID != "a1" || !bytes.Equal(loadedKey, key) {
		t.Fatal("identity not restored")
	}
	raw, err := os.ReadFile(filepath.Join(store.Dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if !bytes.HasPrefix(raw, []byte(dpapiMagic)) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
			t.Fatal("on Windows the key file must be encrypted with DPAPI")
		}
	} else {
		if !bytes.HasPrefix(raw, []byte("-----BEGIN PRIVATE KEY-----")) {
			t.Fatal("expected a PEM key file")
		}
		info, _ := os.Stat(store.Dir)
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("state directory mode %v, want 0700", info.Mode().Perm())
		}
		info, _ = os.Stat(filepath.Join(store.Dir, keyFile))
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %v, want 0600", info.Mode().Perm())
		}
	}
}

func TestLegacyPlainPEMKeyIsStillReadable(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	key, _ := GenerateKey()
	if err := store.SaveState(State{AgentID: "a1"}); err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	legacy := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
	if err := os.WriteFile(filepath.Join(store.Dir, keyFile), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	_, loaded, err := store.Load()
	if err != nil || !bytes.Equal(loaded, key) {
		t.Fatalf("legacy key not readable: %v", err)
	}
}

func TestRetireDeletesKeysAndAllowsANewEnrollment(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	key, _ := GenerateKey()
	next, _ := GenerateKey()
	if err := store.Save(State{AgentID: "a1"}, key); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePendingKey(next); err != nil {
		t.Fatal(err)
	}
	if err := store.Retire(time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if store.Exists() {
		t.Fatal("identity must not exist after retirement")
	}
	for _, name := range []string{keyFile, pendingFile} {
		if _, err := os.Stat(filepath.Join(store.Dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s must be deleted", name)
		}
	}
	archived, err := os.ReadFile(filepath.Join(store.Dir, "agent.revoked-20261117T100000Z.json"))
	if err != nil || !strings.Contains(string(archived), `"agentId": "a1"`) {
		t.Fatalf("archived identity missing: %v", err)
	}
	if _, _, err := store.Load(); err != ErrNotEnrolled {
		t.Fatalf("Load after retirement = %v, want ErrNotEnrolled", err)
	}
	// retiring twice is harmless
	if err := store.Retire(time.Now()); err != nil {
		t.Fatal(err)
	}
}
