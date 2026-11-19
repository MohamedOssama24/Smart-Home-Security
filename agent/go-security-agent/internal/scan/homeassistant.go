package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"shsc/agent/internal/cloud"
	"shsc/agent/internal/homeassistant"
	"shsc/agent/internal/identity"
)

// LoadHomeAssistant reads the Home Assistant settings stored on this agent (nil: none).
func LoadHomeAssistant(store identity.Store) (*homeassistant.Config, error) {
	data, ok, err := store.LoadHomeAssistant()
	if err != nil || !ok {
		return nil, err
	}
	var cfg homeassistant.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("home assistant settings: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("home assistant settings: %w", err)
	}
	return &cfg, nil
}

// SaveHomeAssistant validates and stores the Home Assistant settings.
func SaveHomeAssistant(store identity.Store, cfg homeassistant.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return store.SaveHomeAssistant(data)
}

// gatewayReader is the default GatewayReader: the settings are read again for each job, so that
// "shsc-agent homeassistant" applies without restarting the service. Home Assistant is read
// only when its address belongs to the authorized networks of the job.
func gatewayReader(store identity.Store, log *slog.Logger, now func() time.Time) GatewayReader {
	return func(ctx context.Context, job Job) (*homeassistant.Inventory, []string) {
		cfg, err := LoadHomeAssistant(store)
		if err != nil {
			log.Warn("home assistant integration disabled", "error", err.Error()) // never contains the token
			return nil, nil
		}
		if cfg == nil {
			return nil, nil
		}
		inScope := func(a netip.Addr) bool {
			for _, p := range job.Prefixes {
				if p.Contains(a.Unmap()) {
					return true
				}
			}
			return false
		}
		return homeassistant.Collect(ctx, *cfg, inScope, now)
	}
}

func homeAssistantBatch(inv homeassistant.Inventory) *cloud.HomeAssistant {
	out := &cloud.HomeAssistant{IP: inv.IP.String(), Version: inv.Version, HTTPS: inv.HTTPS, Truncated: inv.Truncated,
		ObservedAt: inv.ObservedAt, Devices: make([]cloud.GatewayDevice, 0, len(inv.Devices))}
	for _, d := range inv.Devices {
		out.Devices = append(out.Devices, cloud.GatewayDevice{Name: d.Name, Manufacturer: d.Manufacturer,
			Model: d.Model, SWVersion: d.SWVersion, Protocol: d.Protocol, MACs: d.MACs, Entities: d.Entities})
	}
	return out
}
