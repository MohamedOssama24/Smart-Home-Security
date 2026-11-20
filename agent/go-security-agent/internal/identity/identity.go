// Package identity stores the agent identity created at enrollment: the agent/home ids and
// the Ed25519 private key that proves it. The private key never leaves this machine; only
// the public key is sent to the backend.
//
// Files (directory 0700, files 0600, written atomically):
//
//	agent.json      identity (no secrets)
//	agent.key       current private key, PKCS#8 PEM
//	agent.key.next  new key during a rotation, promoted once the backend accepted it
//	ca.pem          optional extra CA certificate given at enrollment (--ca-file)
//	router.json     optional router integration settings with the owner's router
//	                credentials (TR-064, SNMP), protected like the keys; deleted by Retire
//
// On Windows the POSIX modes are not enforced by the OS: the key files are encrypted with
// DPAPI (machine scope) and the directory gets an explicit ACL (see protect_windows.go).
// When the backend reports that the agent was revoked, Retire deletes the keys so that the
// agent stops for good and a new enrollment is possible.
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
	caFile      = "ca.pem"
	routerFile  = "router.json"
	// homeAssistantFile holds the Home Assistant URL and long-lived token (Milestone 15)
	homeAssistantFile = "homeassistant.json"
	// directoryFile and sophosFile hold the people integrations (M24, ADR-083)
	directoryFile = "directory.json"
	sophosFile    = "sophos.json"
	pemType       = "PRIVATE KEY"
	// dpapiMagic prefixes key files encrypted with Windows DPAPI
	dpapiMagic = "SHSC-DPAPI-1\n"
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
	// JobSigningKey is the pinned backend key that signs scan jobs (raw Ed25519, base64url).
	JobSigningKey string `json:"jobSigningKey,omitempty"`
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
	if err := s.Secure(); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
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

// SaveCA copies an extra CA certificate (e.g. the development certificate) into the state
// directory and returns its absolute path.
func (s Store) SaveCA(source string) (string, error) {
	data, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	if block, _ := pem.Decode(data); block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s is not a PEM certificate", source)
	}
	target, err := filepath.Abs(filepath.Join(s.Dir, caFile))
	if err != nil {
		return "", err
	}
	return target, writeAtomic(target, data)
}

// Secure restricts access to the state directory (0700, or an explicit ACL on Windows).
func (s Store) Secure() error {
	return secureDir(s.Dir)
}

// Retire is called when the backend reports that the agent was revoked: the private keys
// are deleted (they will never be accepted again) and the identity is kept only as
// agent.revoked-<time>.json for diagnosis. Afterwards Exists is false and a new enrollment
// with a new token is possible.
func (s Store) Retire(now time.Time) error {
	for _, name := range []string{keyFile, pendingFile, routerFile, homeAssistantFile, directoryFile, sophosFile} {
		if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete %s: %w", name, err)
		}
	}
	archived := fmt.Sprintf("agent.revoked-%s.json", now.UTC().Format("20060102T150405Z"))
	err := os.Rename(filepath.Join(s.Dir, stateFile), filepath.Join(s.Dir, archived))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// SaveRouter stores the router integration settings given by the owner (JSON with the
// router credentials), protected like the private key. They never leave this machine.
func (s Store) SaveRouter(config []byte) error { return s.saveSecret(routerFile, config) }

// LoadRouter returns the router integration settings; ok is false when none are stored.
func (s Store) LoadRouter() (config []byte, ok bool, err error) { return s.loadSecret(routerFile) }

// RemoveRouter deletes the router integration settings.
func (s Store) RemoveRouter() error { return s.removeFile(routerFile) }

// SaveHomeAssistant stores the Home Assistant settings (URL and long-lived token of the owner),
// protected like the private key. They never leave this machine.
func (s Store) SaveHomeAssistant(config []byte) error { return s.saveSecret(homeAssistantFile, config) }

// LoadHomeAssistant returns the Home Assistant settings; ok is false when none are stored.
func (s Store) LoadHomeAssistant() (config []byte, ok bool, err error) {
	return s.loadSecret(homeAssistantFile)
}

// RemoveHomeAssistant deletes the Home Assistant settings.
func (s Store) RemoveHomeAssistant() error { return s.removeFile(homeAssistantFile) }

// SaveIntegration stores the settings of a people integration ("directory" or "sophos"),
// protected like the private key. They never leave this machine.
func (s Store) SaveIntegration(name string, config []byte) error {
	file, err := integrationFile(name)
	if err != nil {
		return err
	}
	return s.saveSecret(file, config)
}

// LoadIntegration returns the settings of a people integration; ok is false when none are stored.
func (s Store) LoadIntegration(name string) (config []byte, ok bool, err error) {
	file, err := integrationFile(name)
	if err != nil {
		return nil, false, err
	}
	return s.loadSecret(file)
}

// RemoveIntegration deletes the settings of a people integration.
func (s Store) RemoveIntegration(name string) error {
	file, err := integrationFile(name)
	if err != nil {
		return err
	}
	return s.removeFile(file)
}

func integrationFile(name string) (string, error) {
	switch name {
	case "directory":
		return directoryFile, nil
	case "sophos":
		return sophosFile, nil
	}
	return "", fmt.Errorf("unknown integration %q", name)
}

func (s Store) saveSecret(name string, config []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := protectKey(config)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, name), data)
}

func (s Store) loadSecret(name string) (config []byte, ok bool, err error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	data, err := unprotectKey(raw)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	return data, true, nil
}

func (s Store) removeFile(name string) error {
	err := os.Remove(filepath.Join(s.Dir, name))
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
	data, err := protectKey(pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}))
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, name), data)
}

func (s Store) readKey(name string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return nil, err
	}
	data, err := unprotectKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
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
