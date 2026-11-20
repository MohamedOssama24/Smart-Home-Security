package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"shsc/agent/internal/agentauth"
	"shsc/agent/internal/cloud"
	"shsc/agent/internal/discovery"
	"shsc/agent/internal/homeassistant"
	"shsc/agent/internal/identities"
	"shsc/agent/internal/portscan"
	"shsc/agent/internal/queue"
)

// Queue kind of the scan uploads (results batches and completions, in order).
const uploadKind = "scan"

// Outcomes of a scan.
const (
	OutcomeCompleted = "COMPLETED"
	OutcomeCancelled = "CANCELLED"
	OutcomeFailed    = "FAILED"
)

// Progress phases.
const (
	PhasePreparing  = "PREPARING"
	PhaseInterfaces = "INTERFACES"
	PhaseDiscovery  = "DISCOVERY"
	PhasePorts      = "PORTS"
	PhaseUploading  = "UPLOADING"
)

const (
	maxBatch            = 500
	maxIconsPerBatch    = 16 // 16 × 32 KB in base64 stays well below the 4 MB request limit
	maxIconsPerScan     = 64
	defaultPollWait     = 20 * time.Second
	defaultProgressTick = 5 * time.Second
	minBackoff          = time.Second
	maxBackoff          = 5 * time.Minute
	tokenMargin         = time.Minute
	uploadsPerFlush     = 50
)

// Discoverer runs the discovery of a job; replaced in tests.
type Discoverer func(ctx context.Context, job Job, progress func(done, total, found int)) ([]discovery.Observation, []string)

// PortScanner scans the ports of the discovered hosts (QUICK and STANDARD); replaced in tests.
type PortScanner func(ctx context.Context, job Job, hosts []netip.Addr, progress func(done, total int)) ([]portscan.Result, []portscan.Summary, []string)

// GatewayReader reads the Home Assistant inventory configured by the owner (nil inventory: not
// configured or not readable, see the warnings); replaced in tests.
type GatewayReader func(ctx context.Context, job Job) (*homeassistant.Inventory, []string)

// MethodPortScan is the observation that carries the port counters of one host.
const MethodPortScan = "PORTSCAN"

// Options configure a Worker. Auth and Queue are required.
type Options struct {
	Auth      agentauth.Service
	Queue     *queue.Queue
	Logger    *slog.Logger
	Discover  Discoverer
	ScanPorts PortScanner
	Gateways  GatewayReader
	// Identities reads who uses the addresses of the job (M24); Firewall is the table filled by
	// the Sophos syslog listener (nil: not running).
	Identities IdentityReader
	Firewall   *identities.Table
	PollWait   time.Duration
	Now        func() time.Time
}

// Worker receives and executes scan jobs. It runs next to the heartbeat loop.
type Worker struct {
	o        Options
	session  *agentauth.Session
	failures int
}

// New prepares a worker.
func New(o Options) *Worker {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Discover == nil {
		o.Discover = discoverer(o.Auth.Store, o.Logger)
	}
	if o.ScanPorts == nil {
		o.ScanPorts = portScanner(o.Logger)
	}
	if o.PollWait <= 0 {
		o.PollWait = defaultPollWait
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Gateways == nil {
		o.Gateways = gatewayReader(o.Auth.Store, o.Logger, o.Now)
	}
	if o.Identities == nil {
		o.Identities = identityReader(o.Auth.Store, o.Firewall, identities.ReadDirectory, o.Logger, o.Now)
	}
	if o.Auth.Now == nil {
		o.Auth.Now = o.Now
	}
	return &Worker{o: o}
}

// Run waits for jobs until ctx is cancelled or the agent is revoked (the heartbeat loop then
// retires the agent). Pending uploads are delivered first, also after a restart.
func (w *Worker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := w.poll(ctx)
		if err == nil {
			w.failures = 0
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if cloud.IsCode(err, "AGENT_REVOKED") {
			w.o.Logger.Warn("scan worker stopped: agent revoked")
			return
		}
		var apiErr *cloud.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			w.session = nil
		}
		w.failures++
		wait := w.backoff()
		w.o.Logger.Warn("scan worker: backend not available", "error", err.Error(), "retryIn", wait.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// poll delivers pending uploads, then waits for one job and executes it.
func (w *Worker) poll(ctx context.Context) error {
	if err := w.login(ctx); err != nil {
		return err
	}
	if err := w.flush(ctx); err != nil {
		return err
	}
	signed, err := w.session.Client.NextJob(ctx, w.session.AccessToken, w.o.PollWait)
	if err != nil || signed == nil {
		return err
	}
	job, err := Verify(*signed, w.session.State.JobSigningKey, w.session.State.AgentID, w.o.Now())
	if err != nil {
		// never executed; the backend fails the scan when the job expires (AGENT_OFFLINE)
		w.o.Logger.Error("scan job refused", "error", err.Error())
		return nil
	}
	return w.execute(ctx, job)
}

// login keeps a valid access token and pins the job signing key of agents enrolled before
// it existed (fetched over the verified TLS channel, then never changed).
func (w *Worker) login(ctx context.Context) error {
	if w.session != nil && w.session.ExpiresAt.Sub(w.o.Now()) > tokenMargin {
		return nil
	}
	session, err := w.o.Auth.Login(ctx)
	if err != nil {
		return err
	}
	if session.State.JobSigningKey == "" {
		info, err := session.Client.Session(ctx, session.AccessToken)
		if err != nil {
			return err
		}
		session.State.JobSigningKey = info.JobSigningKey
		if err := w.o.Auth.Store.SaveState(session.State); err != nil {
			return fmt.Errorf("pin job signing key: %w", err)
		}
		w.o.Logger.Info("job signing key pinned")
	}
	w.session = session
	return nil
}

// execute runs one job: ack, discovery with progress reports and cancellation, then the
// results and the completion go to the persistent queue and are delivered.
func (w *Worker) execute(ctx context.Context, job Job) error {
	log := w.o.Logger.With("scanId", job.ScanID)
	lease, err := w.session.Client.Ack(ctx, w.session.AccessToken, job.ScanID)
	if err != nil {
		var apiErr *cloud.APIError
		if errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 && apiErr.Status != 401 {
			log.Info("scan no longer available", "code", apiErr.Code)
			return nil
		}
		return err
	}
	log.Info("scan started", "targets", len(job.Targets))

	// the scan stops on cancellation, at its maximum duration or when the agent stops
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(job.Limits.MaxDurationSeconds)*time.Second)
	defer cancel()
	var (
		mu           sync.Mutex
		state        = cloud.Progress{Phase: PhasePreparing}
		userCancel   bool
		reportsEnded = make(chan struct{})
	)
	set := func(phase string, percent, found int) {
		mu.Lock()
		state = cloud.Progress{Phase: phase, Percent: percent, DevicesDiscovered: found}
		mu.Unlock()
	}
	tick := time.Duration(lease.ProgressIntervalSeconds) * time.Second
	if tick <= 0 {
		tick = defaultProgressTick
	}
	go func() {
		defer close(reportsEnded)
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			}
			mu.Lock()
			p := state
			mu.Unlock()
			ack, err := w.session.Client.ReportProgress(ctx, w.session.AccessToken, job.ScanID, p)
			if err != nil {
				// offline: keep scanning, results are queued and uploaded later
				log.Warn("progress report failed", "error", err.Error())
				continue
			}
			if ack.CancelRequested {
				log.Info("scan cancelled by the user")
				mu.Lock()
				userCancel = true
				mu.Unlock()
				cancel()
				return
			}
		}
	}()

	set(PhaseInterfaces, 0, 0)
	observations, warnings := w.o.Discover(runCtx, job, func(done, total, found int) {
		percent := 100
		if total > 0 {
			percent = done * 100 / total
		}
		set(PhaseDiscovery, min(percent, 99), found)
	})
	var (
		ports     []portscan.Result
		summaries []portscan.Summary
	)
	if job.Profile != ProfileDiscovery && runCtx.Err() == nil {
		hosts := scanTargets(observations)
		set(PhasePorts, 0, len(hosts))
		var portWarnings []string
		ports, summaries, portWarnings = w.o.ScanPorts(runCtx, job, hosts, func(done, total int) {
			percent := 100
			if total > 0 {
				percent = done * 100 / total
			}
			set(PhasePorts, min(percent, 99), len(hosts))
		})
		warnings = append(warnings, portWarnings...)
		observations = append(observations, summaryObservations(job, summaries, w.o.Now())...)
	}
	var inventory *homeassistant.Inventory
	if runCtx.Err() == nil {
		var haWarnings []string
		inventory, haWarnings = w.o.Gateways(runCtx, job)
		warnings = append(warnings, haWarnings...)
	}
	var people []identities.Identity
	if runCtx.Err() == nil {
		var idWarnings []string
		people, idWarnings = w.o.Identities(runCtx, job)
		warnings = append(warnings, idWarnings...)
	}
	outcome := OutcomeCompleted
	mu.Lock()
	cancelledByUser := userCancel
	mu.Unlock()
	switch {
	case cancelledByUser:
		outcome = OutcomeCancelled
	case ctx.Err() != nil:
		outcome = OutcomeCancelled // agent stopping: partial results, the backend records it
	case runCtx.Err() != nil:
		outcome = OutcomeFailed
	}
	cancel()
	<-reportsEnded

	if err := w.enqueueResults(job, observations, ports, inventory, people, warnings, outcome); err != nil {
		log.Error("cannot queue the scan results", "error", err.Error())
		return err
	}
	log.Info("scan finished, uploading", "outcome", outcome, "hosts", len(observations), "warnings", warnings)
	if ctx.Err() != nil {
		return nil // delivered at the next start
	}
	_, _ = w.session.Client.ReportProgress(ctx, w.session.AccessToken, job.ScanID,
		cloud.Progress{Phase: PhaseUploading, Percent: 100, DevicesDiscovered: len(observations)})
	return w.flush(ctx)
}

type upload struct {
	Op       string              `json:"op"` // results | complete
	ScanID   string              `json:"scanId"`
	Batch    *cloud.ResultsBatch `json:"batch,omitempty"`
	Complete *cloud.Completion   `json:"complete,omitempty"`
}

// enqueueResults writes every batch and then the completion to the persistent queue.
func (w *Worker) enqueueResults(job Job, obs []discovery.Observation, ports []portscan.Result,
	inventory *homeassistant.Inventory, people []identities.Identity, warnings []string, outcome string) error {
	ctx := context.Background() // must be written even while stopping
	batches := 0
	for start := 0; ; start += maxBatch {
		end := min(start+maxBatch, len(obs))
		items := make([]cloud.Observation, 0, end-start)
		for _, o := range obs[start:end] {
			items = append(items, cloud.Observation{IP: o.IP.String(), MAC: o.MAC, Method: o.Method,
				Interface: o.Interface, Hostname: o.Hostname, Details: o.Details, ObservedAt: o.ObservedAt})
		}
		u := upload{Op: "results", ScanID: job.ScanID,
			Batch: &cloud.ResultsBatch{SchemaVersion: cloud.SchemaVersion, BatchSeq: batches, Observations: items}}
		if err := w.enqueue(ctx, fmt.Sprintf("%s/results/%d", job.ScanID, batches), u); err != nil {
			return err
		}
		batches++
		if end >= len(obs) {
			break
		}
	}
	// open ports go in their own batches, after the hosts they belong to
	for start := 0; start < len(ports); start += maxBatch {
		end := min(start+maxBatch, len(ports))
		items := make([]cloud.PortResult, 0, end-start)
		for _, p := range ports[start:end] {
			items = append(items, portResult(p))
		}
		u := upload{Op: "results", ScanID: job.ScanID, Batch: &cloud.ResultsBatch{SchemaVersion: cloud.SchemaVersion,
			BatchSeq: batches, Observations: []cloud.Observation{}, Ports: items}}
		if err := w.enqueue(ctx, fmt.Sprintf("%s/results/%d", job.ScanID, batches), u); err != nil {
			return err
		}
		batches++
	}
	// M23: device icons in their own small batches (at most maxIconsPerScan per scan)
	var icons []cloud.DeviceIcon
	for _, o := range obs {
		if o.Icon != nil && len(icons) < maxIconsPerScan {
			icons = append(icons, cloud.DeviceIcon{IP: o.IP.String(), Origin: o.Icon.Origin,
				ContentType: o.Icon.ContentType, Width: o.Icon.Width, Height: o.Icon.Height, Data: o.Icon.Data,
				ObservedAt: o.ObservedAt})
		}
	}
	for start := 0; start < len(icons); start += maxIconsPerBatch {
		end := min(start+maxIconsPerBatch, len(icons))
		u := upload{Op: "results", ScanID: job.ScanID, Batch: &cloud.ResultsBatch{SchemaVersion: cloud.SchemaVersion,
			BatchSeq: batches, Observations: []cloud.Observation{}, Icons: icons[start:end]}}
		if err := w.enqueue(ctx, fmt.Sprintf("%s/results/%d", job.ScanID, batches), u); err != nil {
			return err
		}
		batches++
	}
	// the Home Assistant inventory travels in its own batch (docs/24 §3)
	if inventory != nil {
		u := upload{Op: "results", ScanID: job.ScanID, Batch: &cloud.ResultsBatch{SchemaVersion: cloud.SchemaVersion,
			BatchSeq: batches, Observations: []cloud.Observation{}, HomeAssistant: homeAssistantBatch(*inventory)}}
		if err := w.enqueue(ctx, fmt.Sprintf("%s/results/%d", job.ScanID, batches), u); err != nil {
			return err
		}
		batches++
	}
	// M24: who uses which address, in its own batches after the hosts
	for start := 0; start < len(people); start += maxBatch {
		end := min(start+maxBatch, len(people))
		u := upload{Op: "results", ScanID: job.ScanID, Batch: &cloud.ResultsBatch{SchemaVersion: cloud.SchemaVersion,
			BatchSeq: batches, Observations: []cloud.Observation{}, Identities: identityBatch(people[start:end])}}
		if err := w.enqueue(ctx, fmt.Sprintf("%s/results/%d", job.ScanID, batches), u); err != nil {
			return err
		}
		batches++
	}
	if warnings == nil {
		warnings = []string{}
	}
	done := &cloud.Completion{SchemaVersion: cloud.SchemaVersion, TotalBatches: batches, Outcome: outcome,
		Warnings: warnings}
	if outcome == OutcomeFailed {
		done.ErrorCode = "MAX_DURATION_EXCEEDED"
	}
	return w.enqueue(ctx, job.ScanID+"/complete", upload{Op: "complete", ScanID: job.ScanID, Complete: done})
}

func (w *Worker) enqueue(ctx context.Context, key string, u upload) error {
	payload, err := json.Marshal(u)
	if err != nil {
		return err
	}
	dropped, err := w.o.Queue.Enqueue(ctx, uploadKind, key, payload)
	if dropped > 0 {
		w.o.Logger.Warn("local queue full: oldest messages dropped", "dropped", dropped)
	}
	return err
}

// flush delivers the queued uploads in order. A message the backend refuses for good
// (4xx: scan unknown, finished, invalid) is dropped and logged so it cannot block the queue;
// on a network or server error delivery stops and is retried later.
func (w *Worker) flush(ctx context.Context) error {
	for {
		items, err := w.o.Queue.Peek(ctx, uploadKind, uploadsPerFlush)
		if err != nil || len(items) == 0 {
			return err
		}
		for _, it := range items {
			var u upload
			if err := json.Unmarshal(it.Payload, &u); err != nil {
				w.o.Logger.Error("dropping unreadable queued upload", "key", it.Key)
				_ = w.o.Queue.Ack(ctx, it.ID)
				continue
			}
			err := w.send(ctx, u)
			var apiErr *cloud.APIError
			if errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 &&
				apiErr.Status != http.StatusUnauthorized && apiErr.Status != http.StatusTooManyRequests &&
				apiErr.Status != http.StatusRequestTimeout {
				w.o.Logger.Error("backend refused a scan upload, dropping it", "key", it.Key, "status", apiErr.Status,
					"code", apiErr.Code)
				err = nil
			}
			if err != nil {
				_ = w.o.Queue.MarkAttempt(ctx, it.ID)
				return err
			}
			if err := w.o.Queue.Ack(ctx, it.ID); err != nil {
				return err
			}
		}
	}
}

func (w *Worker) send(ctx context.Context, u upload) error {
	switch {
	case u.Op == "results" && u.Batch != nil:
		return w.session.Client.UploadResults(ctx, w.session.AccessToken, u.ScanID, *u.Batch)
	case u.Op == "complete" && u.Complete != nil:
		status, err := w.session.Client.Complete(ctx, w.session.AccessToken, u.ScanID, *u.Complete)
		if err == nil {
			w.o.Logger.Info("scan completed", "scanId", u.ScanID, "status", status)
		}
		return err
	}
	return &cloud.APIError{Status: http.StatusBadRequest, Code: "UNKNOWN_UPLOAD"}
}

func (w *Worker) backoff() time.Duration {
	d := minBackoff
	for i := 1; i < w.failures && d < maxBackoff; i++ {
		d *= 2
	}
	d = min(d, maxBackoff)
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}
