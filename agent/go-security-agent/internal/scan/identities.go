package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"shsc/agent/internal/cloud"
	"shsc/agent/internal/identities"
	"shsc/agent/internal/identity"
)

// IdentityReader returns which account was last seen on the IP addresses of the job (M24,
// ADR-083); replaced in tests.
type IdentityReader func(ctx context.Context, job Job) ([]identities.Identity, []string)

// LoadDirectory reads the Active Directory settings stored on this agent (nil: none).
func LoadDirectory(store identity.Store) (*identities.DirectoryConfig, error) {
	var cfg identities.DirectoryConfig
	ok, err := loadIntegration(store, "directory", &cfg)
	if err != nil || !ok {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("active directory settings: %w", err)
	}
	return &cfg, nil
}

// SaveDirectory validates and stores the Active Directory settings.
func SaveDirectory(store identity.Store, cfg identities.DirectoryConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	return saveIntegration(store, "directory", cfg)
}

// LoadSophos reads the Sophos settings stored on this agent (nil: none).
func LoadSophos(store identity.Store) (*identities.SophosConfig, error) {
	var cfg identities.SophosConfig
	ok, err := loadIntegration(store, "sophos", &cfg)
	if err != nil || !ok {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("sophos settings: %w", err)
	}
	return &cfg, nil
}

// SaveSophos validates and stores the Sophos settings.
func SaveSophos(store identity.Store, cfg identities.SophosConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	return saveIntegration(store, "sophos", cfg)
}

func loadIntegration(store identity.Store, name string, v any) (bool, error) {
	data, ok, err := store.LoadIntegration(name)
	if err != nil || !ok {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("%s settings: %w", name, err)
	}
	return true, nil
}

func saveIntegration(store identity.Store, name string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return store.SaveIntegration(name, data)
}

// inScope reports whether an address belongs to the authorized networks of the job.
func inScope(job Job) func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		for _, p := range job.Prefixes {
			if p.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	}
}

// identityReader is the default IdentityReader. The domain controller is read only when its
// address belongs to the authorized networks of the job; the Sophos identities come from the
// syslog listener (firewall table, nil when not configured); the settings are read again for
// each job. Only identities of in-scope addresses are returned.
func identityReader(store identity.Store, firewall *identities.Table, read func(context.Context, identities.DirectoryConfig) ([]identities.Identity, error),
	log *slog.Logger, now func() time.Time) IdentityReader {
	return func(ctx context.Context, job Job) ([]identities.Identity, []string) {
		scope := inScope(job)
		var (
			fromDC   []identities.Identity
			warnings []string
		)
		cfg, err := LoadDirectory(store)
		switch {
		case err != nil:
			log.Warn("active directory integration disabled", "error", err.Error()) // never contains the password
		case cfg == nil:
		case !scope(cfg.ServerIP()):
			warnings = append(warnings, "DIRECTORY_OUT_OF_SCOPE")
		default:
			fromDC, err = read(ctx, *cfg)
			if err != nil {
				log.Warn("active directory logons not readable", "error", err.Error())
				warnings = append(warnings, "DIRECTORY_UNREACHABLE")
			}
		}
		var fromFirewall []identities.Identity
		if firewall != nil {
			if sophos, err := LoadSophos(store); err == nil && sophos != nil {
				if scope(sophos.FirewallIP()) {
					fromFirewall = firewall.Snapshot(now().Add(-identities.DefaultHours*time.Hour), scope)
				} else {
					warnings = append(warnings, "FIREWALL_OUT_OF_SCOPE")
				}
			}
		}
		var out []identities.Identity
		for _, id := range identities.Merge(fromDC, fromFirewall) {
			if scope(id.IP) {
				out = append(out, id)
			}
		}
		return out, warnings
	}
}

func identityBatch(ids []identities.Identity) []cloud.Identity {
	out := make([]cloud.Identity, 0, len(ids))
	for _, id := range ids {
		out = append(out, cloud.Identity{IP: id.IP.String(), Account: id.Account, Source: id.Source,
			ObservedAt: id.ObservedAt})
	}
	return out
}
