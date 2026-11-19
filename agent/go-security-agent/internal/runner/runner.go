// Package runner is the long-running loop of the agent service (docs/03-AGENT-PROTOCOL.md
// §3-§5, §8): it keeps a short-lived access token, sends a heartbeat with the
// self-diagnosis, delivers the local event queue and reacts to the backend:
//
//   - network or server errors: the agent keeps running, events stay in the SQLite queue
//     and the connection is retried with exponential backoff and jitter (1 s → 5 min);
//     when the backend is reachable again a CONNECTION_RESTORED event reports the outage;
//   - AGENT_REVOKED: the agent stops for good, deletes the unsent queue and its keys.
//
// The heartbeat interval is set by the backend (25 s by default), so that a revocation is
// noticed within 30 s even without other traffic.
package runner

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"runtime"
	"strings"
	"time"

	"shsc/agent/internal/agentauth"
	"shsc/agent/internal/buildinfo"
	"shsc/agent/internal/capabilities"
	"shsc/agent/internal/cloud"
	"shsc/agent/internal/queue"
)

// ErrRevoked is returned by Run when the backend revoked this agent.
var ErrRevoked = errors.New("the agent has been revoked from the dashboard; enroll it again with a new token")

// Event types sent to the backend.
const (
	EventStarted             = "AGENT_STARTED"
	EventStopped             = "AGENT_STOPPED"
	EventCapabilitiesChanged = "CAPABILITIES_CHANGED"
	EventConnectionRestored  = "CONNECTION_RESTORED"
	EventQueueOverflow       = "QUEUE_OVERFLOW"
)

const (
	eventKind       = "event"
	eventBatch      = 100
	maxBatchesCycle = 10
	tokenMargin     = time.Minute
	maxErrorLength  = 300
)

// Defaults of Options.
const (
	DefaultInterval          = 25 * time.Second
	DefaultMinBackoff        = time.Second
	DefaultMaxBackoff        = 5 * time.Minute
	DefaultCapabilitiesEvery = 10 * time.Minute
	minServerInterval        = 10 * time.Second
	maxServerInterval        = 5 * time.Minute
)

// Options configure a Runner. Zero values use the defaults.
type Options struct {
	Auth              agentauth.Service
	Queue             *queue.Queue
	Logger            *slog.Logger
	Detect            func() capabilities.Report
	Interfaces        func() ([]capabilities.Interface, error)
	Interval          time.Duration
	MinBackoff        time.Duration
	MaxBackoff        time.Duration
	CapabilitiesEvery time.Duration
	// Background, if set, runs next to the heartbeat loop (the scan job worker). It is
	// stopped, and waited for, before the agent stops or retires after a revocation, so that it
	// never writes to the queue after it was purged.
	Background func(ctx context.Context)
	// FixedInterval ignores the interval proposed by the backend (tests).
	FixedInterval bool
	Now           func() time.Time
}

// Runner is the agent service loop. It is not safe for concurrent use.
type Runner struct {
	o            Options
	session      *agentauth.Session
	started      time.Time
	interval     time.Duration
	failures     int
	offlineSince time.Time
	lastError    string
	sentHash     string
	caps         *capabilities.Report
	capsAt       time.Time
}

// New prepares a runner.
func New(o Options) *Runner {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Detect == nil {
		o.Detect = capabilities.Detect
	}
	if o.Interfaces == nil {
		o.Interfaces = capabilities.Interfaces
	}
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = DefaultMinBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultMaxBackoff
	}
	if o.CapabilitiesEvery <= 0 {
		o.CapabilitiesEvery = DefaultCapabilitiesEvery
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Auth.Now == nil {
		o.Auth.Now = o.Now
	}
	return &Runner{o: o, interval: o.Interval}
}

// Run works until ctx is cancelled (returns nil) or the agent is revoked (returns ErrRevoked).
func (r *Runner) Run(ctx context.Context) error {
	state, _, err := r.o.Auth.Store.Load()
	if err != nil {
		return err
	}
	r.started = r.o.Now()
	r.o.Logger.Info("agent started", "agentId", state.AgentID, "homeId", state.HomeID,
		"version", buildinfo.Get().Version)
	r.enqueue(ctx, EventStarted, map[string]any{"agentVersion": buildinfo.Get().Version,
		"os": runtime.GOOS, "arch": runtime.GOARCH})

	bgCtx, bgCancel := context.WithCancel(ctx)
	bgDone := make(chan struct{})
	go func() {
		defer close(bgDone)
		if r.o.Background != nil {
			r.o.Background(bgCtx)
		}
	}()
	stopBackground := func() {
		bgCancel()
		<-bgDone
	}

	for {
		wait, err := r.cycle(ctx)
		if errors.Is(err, ErrRevoked) {
			stopBackground()
			r.retire()
			return ErrRevoked
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			stopBackground()
			r.shutdown()
			return nil
		case <-timer.C:
		}
	}
}

// cycle runs one heartbeat + delivery round and returns how long to wait before the next.
func (r *Runner) cycle(ctx context.Context) (time.Duration, error) {
	r.refreshCapabilities(ctx)
	err := r.exchange(ctx)
	if err == nil {
		if !r.offlineSince.IsZero() {
			offline := r.o.Now().Sub(r.offlineSince)
			r.o.Logger.Info("backend reachable again", "offlineSeconds", int64(offline.Seconds()),
				"failedAttempts", r.failures)
			r.enqueue(ctx, EventConnectionRestored, map[string]any{
				"offlineSeconds": int64(offline.Seconds()), "failedAttempts": r.failures})
			r.offlineSince = time.Time{}
			if err := r.flushEvents(ctx); err != nil && cloud.IsCode(err, "AGENT_REVOKED") {
				return 0, ErrRevoked
			}
		}
		r.failures = 0
		r.lastError = ""
		// up to 10 % earlier, never later: spreads agents without delaying revocation checks
		return r.interval - time.Duration(rand.Int64N(int64(r.interval)/10+1)), nil
	}
	if cloud.IsCode(err, "AGENT_REVOKED") {
		return 0, ErrRevoked
	}
	var apiErr *cloud.APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		r.session = nil // token expired or rotated elsewhere: log in again
	}
	if r.offlineSince.IsZero() && transient(err) {
		r.offlineSince = r.o.Now()
	}
	r.failures++
	r.lastError = truncate(err.Error())
	wait := r.backoff()
	r.o.Logger.Warn("backend exchange failed", "error", err.Error(), "attempt", r.failures,
		"retryIn", wait.Round(time.Millisecond).String())
	return wait, nil
}

func (r *Runner) exchange(ctx context.Context) error {
	if r.session == nil || r.session.ExpiresAt.Sub(r.o.Now()) < tokenMargin {
		session, err := r.o.Auth.Login(ctx)
		if err != nil {
			return err
		}
		r.session = session
	}
	ifaces, err := r.o.Interfaces()
	if err != nil {
		r.o.Logger.Warn("cannot list network interfaces", "error", err.Error())
		ifaces = []capabilities.Interface{}
	}
	hash := capabilities.Hash(ifaces)
	depth, _, err := r.o.Queue.Stats(ctx)
	if err != nil {
		return fmt.Errorf("read queue: %w", err)
	}
	caps := *r.caps
	caps.Warnings = append([]string{}, caps.Warnings...)
	if len(ifaces) == 0 {
		caps.Warnings = append(caps.Warnings, capabilities.WarnNoInterfaces)
	}
	req := cloud.HeartbeatRequest{
		SchemaVersion:  cloud.SchemaVersion,
		AgentVersion:   buildinfo.Get().Version,
		UptimeSeconds:  int64(r.o.Now().Sub(r.started).Seconds()),
		InterfacesHash: hash,
		Capabilities:   caps,
		QueueDepth:     depth,
		LastError:      r.lastError,
	}
	if hash != r.sentHash {
		req.Interfaces = ifaces
	}
	resp, err := r.session.Client.Heartbeat(ctx, r.session.AccessToken, req)
	if err != nil {
		return err
	}
	r.sentHash = hash
	if !r.o.FixedInterval && resp.HeartbeatIntervalSeconds > 0 {
		r.interval = clamp(time.Duration(resp.HeartbeatIntervalSeconds)*time.Second, minServerInterval, maxServerInterval)
	}
	if skew := resp.ServerTime.Sub(r.o.Now()); !resp.ServerTime.IsZero() && (skew > 20*time.Second || skew < -20*time.Second) {
		r.o.Logger.Warn("local clock differs from the server clock; fix the system time", "skew", skew.Round(time.Second).String())
	}
	return r.flushEvents(ctx)
}

// flushEvents delivers queued events in batches; an event the backend rejects as invalid
// is dropped (and logged) so that it cannot block the queue forever.
func (r *Runner) flushEvents(ctx context.Context) error {
	for batch := 0; batch < maxBatchesCycle; batch++ {
		items, err := r.o.Queue.Peek(ctx, eventKind, eventBatch)
		if err != nil || len(items) == 0 {
			return err
		}
		events := make([]cloud.Event, 0, len(items))
		ids := make([]int64, 0, len(items))
		for _, it := range items {
			var e cloud.Event
			if err := json.Unmarshal(it.Payload, &e); err != nil {
				r.o.Logger.Error("dropping unreadable queued event", "key", it.Key, "error", err.Error())
				_ = r.o.Queue.Ack(ctx, it.ID)
				continue
			}
			events = append(events, e)
			ids = append(ids, it.ID)
		}
		if len(events) == 0 {
			continue
		}
		_, err = r.session.Client.Events(ctx, r.session.AccessToken, events)
		var apiErr *cloud.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest {
			if err := r.sendOneByOne(ctx, events, ids); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			_ = r.o.Queue.MarkAttempt(ctx, ids...)
			return err
		}
		if err := r.o.Queue.Ack(ctx, ids...); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) sendOneByOne(ctx context.Context, events []cloud.Event, ids []int64) error {
	for i, e := range events {
		_, err := r.session.Client.Events(ctx, r.session.AccessToken, []cloud.Event{e})
		var apiErr *cloud.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest {
			r.o.Logger.Error("backend rejected an event, dropping it", "type", e.Type, "id", e.ID, "error", err.Error())
		} else if err != nil {
			_ = r.o.Queue.MarkAttempt(ctx, ids[i:]...)
			return err
		}
		if err := r.o.Queue.Ack(ctx, ids[i]); err != nil {
			return err
		}
	}
	return nil
}

// refreshCapabilities re-runs the self-diagnosis periodically; a change becomes an event.
func (r *Runner) refreshCapabilities(ctx context.Context) {
	now := r.o.Now()
	if r.caps != nil && now.Sub(r.capsAt) < r.o.CapabilitiesEvery {
		return
	}
	next := r.o.Detect()
	if r.caps == nil {
		r.o.Logger.Info("capabilities", "privileged", next.Privileged, "arp", next.ARP, "icmp", next.ICMP,
			"warnings", next.Warnings)
	} else if !capabilities.Equal(*r.caps, next) {
		r.o.Logger.Info("capabilities changed", "arp", next.ARP, "icmp", next.ICMP, "privileged", next.Privileged)
		r.enqueue(ctx, EventCapabilitiesChanged, map[string]any{
			"previous": *r.caps, "current": next})
	}
	r.caps = &next
	r.capsAt = now
}

// enqueue writes an event to the persistent queue (never lost because of a network outage).
func (r *Runner) enqueue(ctx context.Context, typ string, detail map[string]any) {
	e := cloud.Event{ID: newEventID(), Type: typ, OccurredAt: r.o.Now().UTC().Truncate(time.Millisecond), Detail: detail}
	payload, err := json.Marshal(e)
	if err != nil {
		r.o.Logger.Error("cannot encode event", "type", typ, "error", err.Error())
		return
	}
	// recorded even if the agent is stopping: an event must not be lost because of a cancellation
	dropped, err := r.o.Queue.Enqueue(context.WithoutCancel(ctx), eventKind, e.ID, payload)
	if err != nil {
		r.o.Logger.Error("cannot queue event", "type", typ, "error", err.Error())
		return
	}
	if dropped > 0 {
		r.o.Logger.Warn("local queue full: oldest messages dropped", "dropped", dropped)
		if typ != EventQueueOverflow {
			r.enqueue(ctx, EventQueueOverflow, map[string]any{"dropped": dropped})
		}
	}
}

// retire stops the agent for good after a revocation.
func (r *Runner) retire() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	purged, err := r.o.Queue.Purge(ctx)
	if err != nil {
		r.o.Logger.Error("cannot empty the local queue", "error", err.Error())
	}
	if err := r.o.Auth.Store.Retire(r.o.Now()); err != nil {
		r.o.Logger.Error("cannot delete the agent keys", "error", err.Error())
	}
	r.o.Logger.Error("agent revoked from the dashboard: stopped, local queue and keys deleted; enroll again with a new token",
		"purgedMessages", purged)
}

// shutdown records the stop and tries a last delivery (bounded, best effort: the event
// stays queued for the next start otherwise).
func (r *Runner) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.enqueue(ctx, EventStopped, map[string]any{"uptimeSeconds": int64(r.o.Now().Sub(r.started).Seconds())})
	if r.session != nil {
		_ = r.flushEvents(ctx)
	}
	r.o.Logger.Info("agent stopped")
}

// backoff is exponential from MinBackoff to MaxBackoff with "equal jitter" (half fixed, half random).
func (r *Runner) backoff() time.Duration {
	d := r.o.MinBackoff
	for i := 1; i < r.failures && d < r.o.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, r.o.MaxBackoff)
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// transient reports errors that mean "backend not reachable or not available".
func transient(err error) bool {
	var apiErr *cloud.APIError
	if !errors.As(err, &apiErr) {
		return true // network, DNS, TLS or timeout error
	}
	return apiErr.Status >= 500 || apiErr.Status == http.StatusTooManyRequests ||
		apiErr.Status == http.StatusRequestTimeout
}

func clamp(d, lo, hi time.Duration) time.Duration {
	return max(lo, min(d, hi))
}

func truncate(s string) string {
	if len(s) <= maxErrorLength {
		return s
	}
	return strings.ToValidUTF8(s[:maxErrorLength], "")
}

// newEventID returns a random UUID (version 4).
func newEventID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic(err) // the OS CSPRNG never fails on supported systems
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
