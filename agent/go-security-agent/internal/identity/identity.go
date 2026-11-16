// Package identity stores the agent identity created at enrollment: the agent/home ids and
// the Ed25519 private key that proves it. The private key never leaves this machine; only
// the public key is sent to the backend.
//
// Files (directory 0700, files 0600, written atomically):
//
//	agent.json      identity (no secrets)
//	agent.key       current private key, PKCS#8 PEM
//	agent.key.next  new key during a rotation, promoted once the backend accepted it
//
// On Windows the POSIX modes are not enforced by the OS: the default directory under
// %ProgramData% inherits its ACL. Protection with DPAPI is planned with the Windows
// service (Milestone 5).
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	stateFile   = "agent.json"
	keyFile     = "agent.key"
	pendingFile = "agent.key.next"
	pemType     = "PRIVATE KEY"
)

// ErrNotEnrolled is returned when no identity is stored.
var ErrNotEnrolled = errors.New("agent is not enrolled (run: shsc-agent enroll)")

// State is the non-secret part of the identity.
type State struct {
	AgentID      string    `json:"agentId"`
	HomeID       string    `json:"homeId"`
	CredentialID string    `json:"credentialId"`
	APIURL       string    `json:"apiUrl"`
	CAFile       string    `json:"caFile,omitempty"`
	EnrolledAt   time.Time `json:"enrolledAt"`
}

// Store reads and writes the identity in a directory.
type Store struct {
	Dir string
}

// DefaultDir returns the system-wide state directory of the agent.
func DefaultDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "SHSC", "agent")
	case "darwin":
		return "/Library/Application Support/SHSC/agent"
	default:
		return "/var/lib/shsc-agent"
	}
}

// GenerateKey creates a new Ed25519 key pair from the OS CSPRNG.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// PublicKey returns the raw 32-byte public key, base64url without padding (API format).
func PublicKey(priv ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// Exists reports whether an identity is stored.
func (s Store) Exists() bool {
	_, err := os.Stat(filepath.Join(s.Dir, stateFile))
	return err == nil
}

// Save writes the private key and then the state.
func (s Store) Save(state State, key ed25519.PrivateKey) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := s.writeKey(keyFile, key); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, stateFile), data)
}

// SaveState rewrites only the state (for example after a key rotation).
func (s Store) SaveState(state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, stateFile), data)
}

// Load returns the state and the current private key.
func (s Store) Load() (State, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil, ErrNotEnrolled
	}
	if err != nil {
		return State{}, nil, fmt.Errorf("read identity: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, nil, fmt.Errorf("identity file is corrupted: %w", err)
	}
	key, err := s.readKey(keyFile)
	if err != nil {
		return State{}, nil, err
	}
	return state, key, nil
}

// SavePendingKey stores the next key before asking the backend to rotate.
func (s Store) SavePendingKey(key ed25519.PrivateKey) error {
	return s.writeKey(pendingFile, key)
}

// PendingKey returns the key of an interrupted rotation, if any.
func (s Store) PendingKey() (ed25519.PrivateKey, bool, error) {
	key, err := s.readKey(pendingFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// PromotePendingKey makes the pending key the current one.
func (s Store) PromotePendingKey() error {
	return os.Rename(filepath.Join(s.Dir, pendingFile), filepath.Join(s.Dir, keyFile))
}

// DiscardPendingKey removes the pending key (rotation rejected).
func (s Store) DiscardPendingKey() error {
	err := os.Remove(filepath.Join(s.Dir, pendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s Store) writeKey(name string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, name), pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}))
}

func (s Store) readKey(name string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemType {
		return nil, fmt.Errorf("%s is not a PEM private key", name)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", name)
	}
	return key, nil
}

// writeAtomic writes to a temporary file with mode 0600 and renames it into place.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
