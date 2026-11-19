package homeassistant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const mockToken = "MOCK.long-lived.token_0123456789" // [MOCK]

func fixedNow() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) }

func all(netip.Addr) bool  { return true }
func none(netip.Addr) bool { return false }

// mockHA is a [MOCK] Home Assistant REST API with three devices.
func mockHA(t *testing.T, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+mockToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/config":
			_, _ = w.Write([]byte(`{"version":"2026.11.1","location_name":"[MOCK] Casa","latitude":45.1}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/template":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || !strings.Contains(body["template"], "device_attr") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`[
 {"n":"[MOCK] Sensore porta","ma":"Aqara","mo":"MCCGQ11LM","sw":null,"ids":[["zha","00:15:8d:00:01:02:03:04"]],"conn":[],"e":3},
 {"n":"[MOCK] Presa\u0007 smart","ma":"Shelly","mo":"Plug S","sw":"1.14.0","ids":[["shelly","abc"]],"conn":[["mac","AA-BB-CC-00-00-61"],["mac","aa:bb:cc:00:00:61"]],"e":5},
 {"n":"[MOCK] Serratura","ma":"Nuki","mo":"Smart Lock","sw":"4.1","ids":[["matter","deadbeef"]],"conn":[],"e":2},
 {"n":"[MOCK] Termometro","ma":null,"mo":null,"sw":null,"ids":[["xiaomi_ble","x"]],"conn":[],"e":1},
 {"n":"[MOCK] Lampada","ma":"IKEA","mo":"TRADFRI","sw":null,"ids":[["mqtt","zigbee2mqtt_0x1234"]],"conn":[],"e":1},
 {"n":"[MOCK] Meteo","ma":"Met.no","mo":null,"sw":null,"ids":[["met","home"]],"conn":[],"e":4}
]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestCollectReadsAndClassifiesTheInventory(t *testing.T) {
	var requests atomic.Int32
	srv := mockHA(t, &requests)
	defer srv.Close()
	inv, warns := Collect(context.Background(), Config{URL: srv.URL, Token: mockToken}, all, fixedNow)
	if inv == nil {
		t.Fatalf("no inventory, warnings %v", warns)
	}
	if !slices.Equal(warns, []string{WarnPlainHTTP}) {
		t.Fatalf("warnings %v", warns)
	}
	if inv.Version != "2026.11.1" || inv.HTTPS || inv.IP.String() != "127.0.0.1" || !inv.ObservedAt.Equal(fixedNow()) {
		t.Fatalf("inventory %+v", inv)
	}
	got := make([]string, 0, len(inv.Devices))
	for _, d := range inv.Devices {
		got = append(got, d.Protocol)
	}
	want := []string{ProtocolZigbee, ProtocolIP, ProtocolMatter, ProtocolBluetooth, ProtocolZigbee, ProtocolOther}
	if !slices.Equal(got, want) {
		t.Fatalf("protocols %v, want %v", got, want)
	}
	plug := inv.Devices[1]
	if plug.Name != "[MOCK] Presa smart" || !slices.Equal(plug.MACs, []string{"aa:bb:cc:00:00:61"}) || plug.Entities != 5 {
		t.Fatalf("plug %+v", plug)
	}
	if requests.Load() != 2 {
		t.Fatalf("%d requests, want 2 (config + template)", requests.Load())
	}
}

func TestRefusedTokenStopsAfterOneRequest(t *testing.T) {
	var requests atomic.Int32
	srv := mockHA(t, &requests)
	defer srv.Close()
	inv, warns := Collect(context.Background(), Config{URL: srv.URL, Token: "MOCK-wrong-token-0123456789"}, all,
		fixedNow)
	if inv != nil || !slices.Contains(warns, WarnAuthFailed) || requests.Load() != 1 {
		t.Fatalf("inventory %v warnings %v requests %d", inv, warns, requests.Load())
	}
}

func TestOutOfScopeSendsNothing(t *testing.T) {
	var requests atomic.Int32
	srv := mockHA(t, &requests)
	defer srv.Close()
	inv, warns := Collect(context.Background(), Config{URL: srv.URL, Token: mockToken}, none, fixedNow)
	if inv != nil || !slices.Equal(warns, []string{WarnOutOfScope}) || requests.Load() != 0 {
		t.Fatalf("inventory %v warnings %v requests %d", inv, warns, requests.Load())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/config", http.StatusFound)
	}))
	defer srv.Close()
	inv, warns := Collect(context.Background(), Config{URL: srv.URL, Token: mockToken}, all, fixedNow)
	if inv != nil || !slices.Contains(warns, WarnInvalidResponse) || elsewhere.Load() != 0 {
		t.Fatalf("inventory %v warnings %v redirected %d", inv, warns, elsewhere.Load())
	}
}

func TestUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	_, warns := Collect(context.Background(), Config{URL: url, Token: mockToken}, all, fixedNow)
	if !slices.Contains(warns, WarnUnreachable) {
		t.Fatalf("warnings %v", warns)
	}
}

func TestConfigValidation(t *testing.T) {
	valid := Config{URL: "http://192.168.1.10:8123", Token: mockToken}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if valid.Address().String() != "192.168.1.10" || valid.HTTPS() {
		t.Fatal(valid.Address(), valid.HTTPS())
	}
	for _, c := range []Config{
		{URL: "http://homeassistant.local:8123", Token: mockToken}, // names are not resolved
		{URL: "ftp://192.168.1.10", Token: mockToken},
		{URL: "http://user:pw@192.168.1.10", Token: mockToken},
		{URL: "http://192.168.1.10/api", Token: mockToken},
		{URL: "http://192.168.1.10:99999", Token: mockToken},
		{URL: "http://192.168.1.10", Token: "short"},
		{URL: "http://192.168.1.10", Token: "MOCK token with spaces 0123456789"},
		{URL: "https://192.168.1.10", Token: mockToken, TLSServerName: "bad name"},
	} {
		err := c.Validate()
		if err == nil {
			t.Errorf("%s accepted", c.URL)
		} else if strings.Contains(err.Error(), c.Token) {
			t.Errorf("error contains the token: %v", err)
		}
	}
	if s := valid.String(); strings.Contains(s, mockToken) {
		t.Fatal("String() prints the token")
	}
}

// TestRealHomeAssistant runs against a Home Assistant container (docs/24 §6):
// SHSC_HA_TEST_URL=http://127.0.0.1:8123 SHSC_HA_TEST_TOKEN=... go test ./internal/homeassistant
func TestRealHomeAssistant(t *testing.T) {
	url, token := os.Getenv("SHSC_HA_TEST_URL"), os.Getenv("SHSC_HA_TEST_TOKEN")
	if url == "" || token == "" {
		t.Skip("SHSC_HA_TEST_URL / SHSC_HA_TEST_TOKEN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	inv, warns := Collect(ctx, Config{URL: url, Token: token}, all, time.Now)
	if inv == nil {
		t.Fatalf("no inventory, warnings %v", warns)
	}
	if inv.Version == "" || len(inv.Devices) == 0 {
		t.Fatalf("inventory %+v", inv)
	}
	for _, d := range inv.Devices {
		t.Logf("%-10s %-30q %q %q entities=%d macs=%v", d.Protocol, d.Name, d.Manufacturer, d.Model, d.Entities, d.MACs)
	}
	_, refused := Collect(ctx, Config{URL: url, Token: "MOCK-invalid-token-0123456789"}, all, time.Now)
	if !slices.Contains(refused, WarnAuthFailed) {
		t.Fatalf("invalid token: warnings %v", refused)
	}
}
