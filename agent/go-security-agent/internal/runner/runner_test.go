package runner

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"shsc/agent/internal/agentauth"
	"shsc/agent/internal/capabilities"
	"shsc/agent/internal/cloud"
	"shsc/agent/internal/identity"
	"shsc/agent/internal/queue"
)

// backend is a TEST DOUBLE of the agent API (token, heartbeat, events) over real TLS. It can
// simulate an outage (connections dropped, like an unreachable server) and a revocation
// (401 AGENT_REVOKED, like the real backend). The real endpoints are covered by the Java
// integration tests and by the end-to-end check with the real binary (PROJECT_STATUS.md).
type backend struct {
	mu         sync.Mutex
	down       bool
	downHits   int
	revoked    bool
	tokens     int
	heartbeats []cloud.HeartbeatRequest
	events     map[string]cloud.Event
	order      []string
	interval   int
}

func newBackend(t *testing.T) (*backend, identity.Store) {
	t.Helper()
	b := &backend{events: map[string]cloud.Event{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/token", b.token)
	mux.HandleFunc("POST /api/v1/agent/heartbeat", b.heartbeat)
	mux.HandleFunc("POST /api/v1/agent/events", b.receive)
	srv := httptest.NewTLSServer(b.outage(mux))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	store := identity.Store{Dir: filepath.Join(dir, "state")}
	key, _ := identity.GenerateKey()
	if err := store.Save(identity.State{AgentID: "0197a000-0000-7000-8000-000000000001", HomeID: "h1",
		APIURL: srv.URL, CAFile: caFile}, key); err != nil {
		t.Fatal(err)
	}
	return b, store
}

func (b *backend) set(f func(*backend)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f(b)
}

// outage drops the TCP connection without answering, like a server that is not reachable.
func (b *backend) outage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		down := b.down
		if down {
			b.downHits++
		}
		b.mu.Unlock()
		if down {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code})
}

func (b *backend) token(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.revoked {
		problem(w, 401, "AGENT_REVOKED")
		return
	}
	b.tokens++
	_ = json.NewEncoder(w).Encode(cloud.TokenResponse{AccessToken: "shsc_at_test", TokenType: "Bearer",
		ExpiresIn: 600, ExpiresAt: time.Now().Add(10 * time.Minute)})
}

func (b *backend) heartbeat(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.revoked {
		problem(w, 401, "AGENT_REVOKED")
		return
	}
	if r.Header.Get("Authorization") != "Bearer shsc_at_test" {
		problem(w, 401, "UNAUTHORIZED")
		return
	}
	var req cloud.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, 400, "INVALID_REQUEST")
		return
	}
	b.heartbeats = append(b.heartbeats, req)
	_ = json.NewEncoder(w).Encode(cloud.HeartbeatResponse{ServerTime: time.Now(), HeartbeatIntervalSeconds: b.interval})
}

func (b *backend) receive(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.revoked {
		problem(w, 401, "AGENT_REVOKED")
		return
	}
	var body struct {
		Events []cloud.Event `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, 400, "INVALID_REQUEST")
		return
	}
	resp := cloud.EventsResponse{}
	for _, e := range body.Events {
		if e.Type == "UNKNOWN_TYPE" {
			problem(w, 400, "INVALID_EVENT")
			return
		}
	}
	for _, e := range body.Events {
		if _, dup := b.events[e.ID]; dup {
			resp.Duplicates++
			continue
		}
		b.events[e.ID] = e
		b.order = append(b.order, e.Type)
		resp.Accepted++
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (b *backend) eventTypes() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.order...)
}

func (b *backend) heartbeatCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.heartbeats)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func openQueue(t *testing.T, store identity.Store) *queue.Queue {
	t.Helper()
	q, err := queue.Open(filepath.Join(store.Dir, "queue.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}

type fakeHost struct {
	mu     sync.Mutex
	caps   capabilities.Report
	ifaces []capabilities.Interface
}

func (h *fakeHost) detect() capabilities.Report {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.caps
}

func (h *fakeHost) interfaces() ([]capabilities.Interface, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]capabilities.Interface{}, h.ifaces...), nil
}

func newRunner(store identity.Store, q *queue.Queue, host *fakeHost) *Runner {
	return New(Options{
		Auth:              agentauth.Service{Store: store},
		Queue:             q,
		Detect:            host.detect,
		Interfaces:        host.interfaces,
		Interval:          20 * time.Millisecond,
		FixedInterval:     true,
		MinBackoff:        5 * time.Millisecond,
		MaxBackoff:        40 * time.Millisecond,
		CapabilitiesEvery: time.Millisecond,
	})
}

func defaultHost() *fakeHost {
	return &fakeHost{
		caps:   capabilities.Report{ARP: capabilities.Raw, ICMP: capabilities.Raw, Warnings: []string{}},
		ifaces: []capabilities.Interface{{Name: "eth0", MTU: 1500, Addresses: []string{"192.168.1.20/24"}}},
	}
}

func TestHeartbeatsCarryDiagnosisAndInterfacesOnlyWhenChanged(t *testing.T) {
	b, store := newBackend(t)
	q := openQueue(t, store)
	host := defaultHost()
	r := newRunner(store, q, host)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	waitFor(t, "3 heartbeats", 5*time.Second, func() bool { return b.heartbeatCount() >= 3 })
	host.mu.Lock()
	host.ifaces = append(host.ifaces, capabilities.Interface{Name: "wlan0", MTU: 1500, Addresses: []string{"192.168.2.5/24"}})
	host.mu.Unlock()
	start := b.heartbeatCount()
	waitFor(t, "heartbeats after interface change", 5*time.Second, func() bool { return b.heartbeatCount() >= start+3 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v after cancel", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	first := b.heartbeats[0]
	if first.SchemaVersion != cloud.SchemaVersion || first.Capabilities.ARP != capabilities.Raw ||
		len(first.Interfaces) != 1 || first.InterfacesHash == "" || first.AgentVersion == "" {
		t.Fatalf("unexpected first heartbeat %+v", first)
	}
	if b.heartbeats[1].Interfaces != nil {
		t.Fatal("unchanged interfaces must not be sent again")
	}
	sentAgain := 0
	for _, hb := range b.heartbeats[start:] {
		if len(hb.Interfaces) == 2 {
			sentAgain++
		}
	}
	if sentAgain != 1 {
		t.Fatalf("changed interface list must be sent exactly once, sent %d times", sentAgain)
	}
	if b.tokens != 1 {
		t.Fatalf("the access token must be reused while valid, got %d logins", b.tokens)
	}
	if !contains(b.order, EventStarted) {
		t.Fatalf("AGENT_STARTED not delivered: %v", b.order)
	}
}

// Revocation: the agent must notice it at the next heartbeat (interval ≤ 25 s in
// production, so within 30 s), stop, delete its unsent queue and its keys.
func TestRevocationStopsTheAgentAndDeletesQueueAndKeys(t *testing.T) {
	b, store := newBackend(t)
	q := openQueue(t, store)
	r := newRunner(store, q, defaultHost())
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	waitFor(t, "first heartbeat", 5*time.Second, func() bool { return b.heartbeatCount() >= 1 })

	// a message waiting in the queue when the revocation arrives must be deleted
	if _, err := q.Enqueue(context.Background(), eventKind, "pending", []byte(`{"id":"pending","type":"AGENT_STARTED"}`)); err != nil {
		t.Fatal(err)
	}
	b.set(func(b *backend) { b.revoked = true })
	revokedAt := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("Run returned %v, want ErrRevoked", err)
		}
		// with a 20 ms test interval the stop must follow within a few intervals
		if elapsed := time.Since(revokedAt); elapsed > 2*time.Second {
			t.Fatalf("revocation noticed after %v", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent kept running after the revocation")
	}
	if count, _, _ := q.Stats(context.Background()); count != 0 {
		t.Fatalf("queue must be empty after revocation, %d messages left", count)
	}
	if store.Exists() {
		t.Fatal("identity must be retired")
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "agent.key")); !os.IsNotExist(err) {
		t.Fatal("private key must be deleted")
	}
}

func TestProductionIntervalDetectsRevocationWithin30Seconds(t *testing.T) {
	if DefaultInterval >= 30*time.Second || maxServerInterval < DefaultInterval {
		t.Fatalf("default heartbeat interval %v does not guarantee revocation within 30 s", DefaultInterval)
	}
	r := New(Options{})
	if r.interval != DefaultInterval {
		t.Fatalf("interval %v", r.interval)
	}
}

// Offline: the backend becomes unreachable; the agent keeps running with backoff, events
// produced meanwhile stay in the SQLite queue and are delivered once the backend is back,
// followed by CONNECTION_RESTORED.
func TestOfflineKeepsRunningQueuesEventsAndRecovers(t *testing.T) {
	b, store := newBackend(t)
	q := openQueue(t, store)
	host := defaultHost()
	r := newRunner(store, q, host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, "AGENT_STARTED delivered", 5*time.Second, func() bool { return contains(b.eventTypes(), EventStarted) })

	b.set(func(b *backend) { b.down = true })
	beforeOutage := b.heartbeatCount()
	// a capability change while offline produces an event that must not be lost
	host.mu.Lock()
	host.caps = capabilities.Report{ARP: capabilities.OSTable, ICMP: capabilities.Unavailable,
		Warnings: []string{capabilities.WarnARPTableOnly, capabilities.WarnICMPUnavailable}}
	host.mu.Unlock()
	waitFor(t, "event queued while offline", 5*time.Second, func() bool {
		items, _ := q.Peek(context.Background(), eventKind, 10)
		for _, it := range items {
			var e cloud.Event
			if json.Unmarshal(it.Payload, &e) == nil && e.Type == EventCapabilitiesChanged {
				return true
			}
		}
		return false
	})
	time.Sleep(150 * time.Millisecond) // several failed attempts with backoff
	b.mu.Lock()
	hits := b.downHits
	b.mu.Unlock()
	if hits < 2 {
		t.Fatalf("expected repeated attempts with backoff while offline, got %d", hits)
	}
	select {
	case err := <-done:
		t.Fatalf("the agent stopped while offline: %v", err)
	default:
	}
	if b.heartbeatCount() != beforeOutage {
		t.Fatal("no heartbeat can arrive during the outage")
	}

	b.set(func(b *backend) { b.down = false })
	waitFor(t, "recovery", 5*time.Second, func() bool {
		types := b.eventTypes()
		return contains(types, EventCapabilitiesChanged) && contains(types, EventConnectionRestored)
	})
	waitFor(t, "queue drained", 5*time.Second, func() bool {
		count, _, _ := q.Stats(context.Background())
		return count == 0
	})
	b.mu.Lock()
	last := b.heartbeats[len(b.heartbeats)-1]
	restored := cloud.Event{}
	for _, e := range b.events {
		if e.Type == EventConnectionRestored {
			restored = e
		}
	}
	b.mu.Unlock()
	if last.Capabilities.ARP != capabilities.OSTable || len(last.Capabilities.Warnings) != 2 {
		t.Fatalf("heartbeat after recovery must carry the new capabilities: %+v", last.Capabilities)
	}
	if n, ok := restored.Detail["failedAttempts"].(float64); !ok || n < 2 {
		t.Fatalf("CONNECTION_RESTORED must report the failed attempts: %+v", restored.Detail)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEventsSurviveARestartAndAreNotDuplicated(t *testing.T) {
	b, store := newBackend(t)
	b.set(func(b *backend) { b.down = true })
	q := openQueue(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	r := newRunner(store, q, defaultHost())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, "a failed attempt", 5*time.Second, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.downHits > 0
	})
	cancel() // stopped while offline: AGENT_STARTED and AGENT_STOPPED stay queued
	<-done
	if count, _, _ := q.Stats(context.Background()); count != 2 {
		t.Fatalf("expected 2 queued events, got %d", count)
	}

	b.set(func(b *backend) { b.down = false })
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- newRunner(store, q, defaultHost()).Run(ctx2) }()
	waitFor(t, "queued events delivered after restart", 5*time.Second, func() bool {
		count, _, _ := q.Stats(context.Background())
		return count == 0 && len(b.eventTypes()) >= 3
	})
	cancel2()
	<-done2
	types := b.eventTypes()
	if types[0] != EventStarted || types[1] != EventStopped || types[2] != EventStarted {
		t.Fatalf("events must be delivered in order, got %v", types)
	}
}

func TestInvalidEventIsDroppedWithoutBlockingTheQueue(t *testing.T) {
	b, store := newBackend(t)
	q := openQueue(t, store)
	ctx := context.Background()
	for _, e := range []cloud.Event{{ID: "e1", Type: "AGENT_STARTED"}, {ID: "e2", Type: "UNKNOWN_TYPE"}, {ID: "e3", Type: "AGENT_STOPPED"}} {
		payload, _ := json.Marshal(e)
		if _, err := q.Enqueue(ctx, eventKind, e.ID, payload); err != nil {
			t.Fatal(err)
		}
	}
	r := newRunner(store, q, defaultHost())
	session, err := r.o.Auth.Login(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.session = session
	if err := r.flushEvents(ctx); err != nil {
		t.Fatal(err)
	}
	if count, _, _ := q.Stats(ctx); count != 0 {
		t.Fatalf("queue must be empty, %d left", count)
	}
	if got := b.eventTypes(); len(got) != 2 || got[0] != "AGENT_STARTED" || got[1] != "AGENT_STOPPED" {
		t.Fatalf("valid events must be delivered, got %v", got)
	}
}

func TestBackoffGrowsWithJitterAndIsCapped(t *testing.T) {
	r := New(Options{MinBackoff: time.Second, MaxBackoff: 5 * time.Minute})
	for failures, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 5: 16 * time.Second, 30: 5 * time.Minute} {
		r.failures = failures
		for i := 0; i < 20; i++ {
			got := r.backoff()
			if got < want/2 || got > want {
				t.Fatalf("failures=%d backoff %v outside [%v, %v]", failures, got, want/2, want)
			}
		}
	}
}

func TestTransientErrors(t *testing.T) {
	if !transient(errors.New("dial tcp: connection refused")) {
		t.Fatal("network errors are transient")
	}
	for status, want := range map[int]bool{500: true, 503: true, 429: true, 408: true, 400: false, 401: false, 403: false} {
		if got := transient(&cloud.APIError{Status: status}); got != want {
			t.Fatalf("status %d transient=%v", status, got)
		}
	}
}

func TestEventIDsAreRandomUUIDs(t *testing.T) {
	a, b := newEventID(), newEventID()
	if a == b || len(a) != 36 || a[14] != '4' {
		t.Fatalf("bad ids %s %s", a, b)
	}
}
