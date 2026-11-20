package scan

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"shsc/agent/internal/cloud"
	"shsc/agent/internal/identities"
	"shsc/agent/internal/identity"
	"shsc/agent/internal/queue"
)

// [MOCK] addresses (192.168.63.0/24 authorized, 192.168.65.0/24 not) and accounts.

func TestIdentityReaderReadsOnlyInScope(t *testing.T) {
	store := identity.Store{Dir: t.TempDir()}
	now := func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) }
	job := Job{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.63.0/24")}}
	calls := 0
	fromDC := []identities.Identity{
		{IP: netip.MustParseAddr("192.168.63.21"), Account: "mario.rossi", Source: identities.SourceDirectory, ObservedAt: now().Add(-time.Hour)},
		{IP: netip.MustParseAddr("192.168.65.9"), Account: "fuori", Source: identities.SourceDirectory, ObservedAt: now()},
	}
	read := func(_ context.Context, cfg identities.DirectoryConfig) ([]identities.Identity, error) {
		calls++
		if cfg.Password != "MOCK-password" {
			return nil, errors.New("wrong password")
		}
		return fromDC, nil
	}
	firewall := identities.NewTable()
	firewall.Put(identities.Identity{IP: netip.MustParseAddr("192.168.63.21"), Account: "mario.rossi", Source: identities.SourceFirewall, ObservedAt: now()})
	firewall.Put(identities.Identity{IP: netip.MustParseAddr("192.168.63.22"), Account: "anna.bianchi", Source: identities.SourceFirewall, ObservedAt: now()})
	reader := identityReader(store, firewall, read, slog.New(slog.DiscardHandler), now)

	// nothing configured: nothing read, no warning
	if ids, warns := reader(context.Background(), job); len(ids) != 0 || len(warns) != 0 || calls != 0 {
		t.Fatalf("not configured: %v %v %d", ids, warns, calls)
	}
	// domain controller outside the authorized networks: never contacted
	if err := SaveDirectory(store, identities.DirectoryConfig{Server: "192.168.65.2", User: "shsc-reader", Password: "MOCK-password"}); err != nil {
		t.Fatal(err)
	}
	if _, warns := reader(context.Background(), job); calls != 0 || len(warns) != 1 || warns[0] != "DIRECTORY_OUT_OF_SCOPE" {
		t.Fatalf("out of scope: %v %d", warns, calls)
	}
	if err := SaveDirectory(store, identities.DirectoryConfig{Server: "192.168.63.2", User: "shsc-reader", Password: "MOCK-password"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveSophos(store, identities.SophosConfig{Firewall: "192.168.63.1"}); err != nil {
		t.Fatal(err)
	}
	ids, warns := reader(context.Background(), job)
	if calls != 1 || len(warns) != 0 || len(ids) != 2 {
		t.Fatalf("configured: %+v %v %d", ids, warns, calls)
	}
	for _, id := range ids {
		if id.IP.String() == "192.168.63.21" && id.Source != identities.SourceFirewall {
			t.Fatalf("the most recent identity must win: %+v", id)
		}
	}
	// the stored settings are protected and never contain the password in clear
	cfg, err := LoadDirectory(store)
	if err != nil || cfg == nil || cfg.User != "shsc-reader" {
		t.Fatalf("load: %+v %v", cfg, err)
	}
}

func TestIdentitiesTravelInTheirOwnBatch(t *testing.T) {
	q, err := queue.Open(filepath.Join(t.TempDir(), "q.db"), queue.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	w := New(Options{Queue: q})
	ids := []identities.Identity{{IP: netip.MustParseAddr("192.168.63.21"), Account: "mario.rossi",
		Source: identities.SourceDirectory, ObservedAt: time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)}}
	if err := w.enqueueResults(Job{ScanID: "s1"}, nil, nil, nil, ids, nil, OutcomeCompleted); err != nil {
		t.Fatal(err)
	}
	items, err := q.Peek(context.Background(), uploadKind, 10)
	if err != nil || len(items) != 3 {
		t.Fatalf("items: %d %v", len(items), err)
	}
	var u upload
	if err := json.Unmarshal(items[1].Payload, &u); err != nil {
		t.Fatal(err)
	}
	want := cloud.Identity{IP: "192.168.63.21", Account: "mario.rossi", Source: "DIRECTORY", ObservedAt: ids[0].ObservedAt}
	if u.Batch == nil || u.Batch.BatchSeq != 1 || len(u.Batch.Identities) != 1 || u.Batch.Identities[0] != want {
		t.Fatalf("batch: %+v", u.Batch)
	}
	var done upload
	_ = json.Unmarshal(items[2].Payload, &done)
	if done.Complete == nil || done.Complete.TotalBatches != 2 {
		t.Fatalf("completion: %+v", done.Complete)
	}
}
