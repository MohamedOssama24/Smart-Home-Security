package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"shsc/agent/internal/discovery"
	"shsc/agent/internal/identity"
)

// LoadRouter reads the router integration settings stored on this agent (nil: none).
func LoadRouter(store identity.Store) (*discovery.RouterConfig, error) {
	data, ok, err := store.LoadRouter()
	if err != nil || !ok {
		return nil, err
	}
	var cfg discovery.RouterConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("router settings: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("router settings: %w", err)
	}
	return &cfg, nil
}

// SaveRouter validates and stores the router integration settings.
func SaveRouter(store identity.Store, cfg discovery.RouterConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return store.SaveRouter(data)
}

// discoverer is the default Discoverer: the router settings are read again for each job, so
// that a change made with "shsc-agent router" applies without restarting the service.
func discoverer(store identity.Store, log *slog.Logger) Discoverer {
	return func(ctx context.Context, job Job, progress func(done, total, found int)) ([]discovery.Observation, []string) {
		ifaces, err := discovery.LocalInterfaces()
		if err != nil {
			return nil, []string{discovery.WarnTargetNotConnected}
		}
		router, err := LoadRouter(store)
		if err != nil {
			log.Warn("router integration disabled", "error", err.Error()) // never contains a secret
		}
		plan := discovery.MakePlan(job.Prefixes, ifaces, job.Limits.MaxHosts)
		return discovery.Run(ctx, plan, discovery.Options{RatePerSecond: job.Limits.RatePerSecond,
			Concurrency: job.Limits.Concurrency, Progress: progress, Router: router})
	}
}
