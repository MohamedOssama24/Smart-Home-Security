package scan

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"shsc/agent/internal/homeassistant"
	"shsc/agent/internal/identity"
)

const mockHAToken = "MOCK.long-lived.token_0123456789" // [MOCK]

func TestGatewayReaderUsesStoredSettingsOnlyInScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/config" {
			_, _ = w.Write([]byte(`{"version":"2026.11.1"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"n":"[MOCK] Sensore","ids":[["zha","x"]],"conn":[],"e":1}]`))
	}))
	defer srv.Close()
	store := identity.Store{Dir: t.TempDir()}
	now := func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) }
	read := gatewayReader(store, slog.New(slog.DiscardHandler), now)

	// not configured: nothing, no warning
	if inv, warns := read(context.Background(), Job{}); inv != nil || warns != nil {
		t.Fatalf("not configured: %v %v", inv, warns)
	}
	if err := SaveHomeAssistant(store, homeassistant.Config{URL: srv.URL, Token: mockHAToken}); err != nil {
		t.Fatal(err)
	}
	// the token is not stored in clear text on disk
	raw, err := os.ReadFile(filepath.Join(store.Dir, "homeassistant.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), mockHAToken) && os.PathSeparator == '\\' {
		t.Fatal("token stored in clear text on Windows (DPAPI expected)")
	}

	outside := Job{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}
	if inv, warns := read(context.Background(), outside); inv != nil ||
		!slices.Equal(warns, []string{homeassistant.WarnOutOfScope}) {
		t.Fatalf("out of scope: %v %v", inv, warns)
	}
	inside := Job{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	inv, warns := read(context.Background(), inside)
	if inv == nil || len(inv.Devices) != 1 || !slices.Equal(warns, []string{homeassistant.WarnPlainHTTP}) {
		t.Fatalf("in scope: %v %v", inv, warns)
	}
	batch, err := json.Marshal(homeAssistantBatch(*inv))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(batch), mockHAToken) || strings.Contains(string(batch), srv.URL) ||
		!strings.Contains(string(batch), `"protocol":"ZIGBEE"`) {
		t.Fatalf("batch %s", batch)
	}
	if err := store.RemoveHomeAssistant(); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadHomeAssistant(store); cfg != nil || err != nil {
		t.Fatalf("after remove: %v %v", cfg, err)
	}
}
