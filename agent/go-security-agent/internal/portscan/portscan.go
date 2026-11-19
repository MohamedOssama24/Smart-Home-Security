// Package portscan finds the open ports of the hosts found by the discovery and identifies
// their services (docs/08-PORT-SCANNING-SERVICES.md).
//
// Safety rules, enforced here and verified by the policy tests:
//   - only the hosts the discovery found, and only when they belong to an authorized and
//     directly connected network (InScope is checked before any packet is sent);
//   - TCP connect only (no raw packets): the connection is closed as soon as it is open;
//   - UDP is never swept: only ports with a protocol-specific, read-only probe are contacted;
//   - the load is bounded: global and per-host rate and concurrency, timeouts, one retry for
//     timeouts, a host that keeps failing is paused;
//   - service detection only reads what a service says or asks the public, unauthenticated
//     information every client gets (banner, HTTP GET /, TLS handshake, RTSP OPTIONS, SMB2
//     NEGOTIATE, IPP Get-Printer-Attributes, ONVIF GetSystemDateAndTime). No login, no
//     credential (default or anonymous), no exploit, no command;
//   - everything a device sends is untrusted input: read with byte and time limits, stored
//     truncated and sanitized.
package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Port states.
const (
	StateOpen         = "OPEN"
	StateClosed       = "CLOSED"
	StateFiltered     = "FILTERED"
	StateOpenFiltered = "OPEN_FILTERED"
	StateUnknown      = "UNKNOWN"
)

// Service status: deduced from the port number only, or confirmed by the protocol.
const (
	StatusProbable  = "PROBABLE"
	StatusConfirmed = "CONFIRMED"
)

// Protocols.
const (
	TCP = "TCP"
	UDP = "UDP"
)

// Warning codes (translated by the dashboard).
const (
	WarnHostPaused   = "PORT_SCAN_HOST_PAUSED"
	WarnOutOfScope   = "PORT_SCAN_OUT_OF_SCOPE"
	WarnIncomplete   = "PORT_SCAN_INCOMPLETE"
	maxEvidenceBytes = 512
	pauseAfterErrors = 5
)

// Service is what was learnt about the service of an open port.
type Service struct {
	Name       string         `json:"name"`
	Product    string         `json:"product,omitempty"`
	Version    string         `json:"version,omitempty"`
	Status     string         `json:"status"`
	Confidence string         `json:"confidence"`
	Evidence   map[string]any `json:"evidence,omitempty"`
	TLS        map[string]any `json:"tls,omitempty"`
}

// Result is an open port. Closed, filtered and silent ports are only counted (Summary).
type Result struct {
	IP         netip.Addr
	Protocol   string
	Port       int
	State      string
	Reason     string
	Service    *Service
	ObservedAt time.Time
}

// Counters count the ports probed on a host per state.
type Counters struct {
	Probed       int `json:"probed"`
	Open         int `json:"open"`
	Closed       int `json:"closed"`
	Filtered     int `json:"filtered,omitempty"`
	OpenFiltered int `json:"openFiltered,omitempty"`
	Unknown      int `json:"unknown,omitempty"`
}

func (c *Counters) add(state string) {
	c.Probed++
	switch state {
	case StateOpen:
		c.Open++
	case StateClosed:
		c.Closed++
	case StateFiltered:
		c.Filtered++
	case StateOpenFiltered:
		c.OpenFiltered++
	default:
		c.Unknown++
	}
}

// Summary is the coverage of one host: what was probed and with which outcome.
type Summary struct {
	IP     netip.Addr
	TCP    Counters
	UDP    Counters
	Paused bool
}

// Limits bound the load of the scan (docs/08 §1).
type Limits struct {
	RatePerSecond        int
	Concurrency          int
	PerHostConcurrency   int
	PerHostRatePerSecond int
	Timeout              time.Duration
}

// Options configure a scan. InScope is required.
type Options struct {
	Profile   Profile
	Lists     Lists
	Limits    Limits
	InScope   func(netip.Addr) bool
	Progress  func(done, total int)
	Now       func() time.Time
	UserAgent string

	// udpPort maps the well-known port of a UDP probe to the port actually used (tests).
	udpPort func(int) int
	// dialTCP replaces the connect of the TCP scan (tests).
	dialTCP func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Run scans the hosts and returns the open ports, the per-host coverage and the warnings.
func Run(ctx context.Context, hosts []netip.Addr, o Options) ([]Result, []Summary, []string) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.udpPort == nil {
		o.udpPort = func(p int) int { return p }
	}
	if o.InScope == nil {
		return nil, nil, []string{WarnOutOfScope}
	}
	lim := normalize(o.Limits)
	global := newBucket(lim.RatePerSecond)
	defer global.stop()

	var (
		mu       sync.Mutex
		results  []Result
		sums     []Summary
		warnings = map[string]bool{}
		done     atomic.Int64
	)
	total := max(1, len(hosts)*(len(o.Profile.TCP)+len(o.Profile.UDP)))
	step := func() {
		d := done.Add(1)
		if o.Progress != nil {
			o.Progress(int(d), total)
		}
	}
	queue := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range max(1, lim.Concurrency/lim.PerHostConcurrency) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range queue {
				if !o.InScope(ip) {
					mu.Lock()
					warnings[WarnOutOfScope] = true
					mu.Unlock()
					continue // never contacted
				}
				h := &hostScan{ip: ip, o: o, lim: lim, global: global, step: step}
				open, sum := h.run(ctx)
				mu.Lock()
				results = append(results, open...)
				sums = append(sums, sum)
				if sum.Paused {
					warnings[WarnHostPaused] = true
				}
				mu.Unlock()
			}
		}()
	}
	for _, ip := range hosts {
		select {
		case queue <- ip:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(queue)
	wg.Wait()
	if ctx.Err() != nil {
		warnings[WarnIncomplete] = true
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.IP != b.IP {
			return a.IP.Less(b.IP)
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
	sort.Slice(sums, func(i, j int) bool { return sums[i].IP.Less(sums[j].IP) })
	out := make([]string, 0, len(warnings))
	for w := range warnings {
		out = append(out, w)
	}
	sort.Strings(out)
	return results, sums, out
}

func normalize(l Limits) Limits {
	if l.RatePerSecond <= 0 {
		l.RatePerSecond = 300
	}
	if l.Concurrency <= 0 {
		l.Concurrency = 256
	}
	if l.PerHostConcurrency <= 0 {
		l.PerHostConcurrency = 8
	}
	l.PerHostConcurrency = min(l.PerHostConcurrency, l.Concurrency)
	if l.PerHostRatePerSecond <= 0 {
		l.PerHostRatePerSecond = 50
	}
	if l.Timeout <= 0 {
		l.Timeout = 1500 * time.Millisecond
	}
	return l
}

// hostScan scans one host: TCP ports, services of the open ones, UDP probes.
type hostScan struct {
	ip     netip.Addr
	o      Options
	lim    Limits
	global *bucket
	host   *bucket
	step   func()
	errors atomic.Int32 // consecutive errors (unreachable host, no route...)
	paused atomic.Bool
}

func (h *hostScan) run(ctx context.Context) ([]Result, Summary) {
	h.host = newBucket(h.lim.PerHostRatePerSecond)
	defer h.host.stop()
	sum := Summary{IP: h.ip}
	var open []Result

	// TCP connect scan, PerHostConcurrency connections at most
	ports := make(chan int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range h.lim.PerHostConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				state, reason := h.connect(ctx, port)
				if state == "" {
					continue // cancelled or paused: not probed
				}
				h.step()
				mu.Lock()
				sum.TCP.add(state)
				if state == StateOpen {
					open = append(open, Result{IP: h.ip, Protocol: TCP, Port: port, State: state, Reason: reason,
						ObservedAt: h.o.Now().UTC()})
				}
				mu.Unlock()
			}
		}()
	}
	for _, port := range h.o.Profile.TCP {
		if ctx.Err() != nil || h.paused.Load() {
			break
		}
		ports <- port
	}
	close(ports)
	wg.Wait()

	// services of the open ports, one at a time on this host
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	for i := range open {
		if ctx.Err() != nil {
			break
		}
		open[i].Service = h.detect(ctx, open[i].Port)
	}

	// UDP: protocol-specific probes only
	for _, port := range h.o.Profile.UDP {
		if ctx.Err() != nil || h.paused.Load() {
			break
		}
		r, ok := h.probeUDP(ctx, port)
		if !ok {
			continue
		}
		h.step()
		sum.UDP.add(r.State)
		if r.State == StateOpen {
			open = append(open, r)
		}
	}
	sum.Paused = h.paused.Load()
	return open, sum
}

// wait applies the global and the per-host rate.
func (h *hostScan) wait(ctx context.Context) bool {
	return h.global.wait(ctx) && h.host.wait(ctx)
}

// connect classifies one TCP port. "" when the scan stopped before the port was probed.
func (h *hostScan) connect(ctx context.Context, port int) (string, string) {
	addr := netip.AddrPortFrom(h.ip, uint16(port))
	dial := (&net.Dialer{Timeout: h.lim.Timeout}).DialContext
	if h.o.dialTCP != nil {
		dial = h.o.dialTCP
	}
	for attempt := 0; attempt < 2; attempt++ { // one retry, only for timeouts
		if h.paused.Load() || !h.wait(ctx) {
			return "", ""
		}
		conn, err := dial(ctx, "tcp", addr.String())
		if err == nil {
			_ = conn.Close() // nothing is sent
			h.errors.Store(0)
			return StateOpen, "syn-ack"
		}
		if ctx.Err() != nil {
			return "", ""
		}
		switch {
		case isRefused(err):
			h.errors.Store(0)
			return StateClosed, "rst"
		case isTimeout(err):
			continue
		default:
			if h.errors.Add(1) >= pauseAfterErrors {
				h.paused.Store(true) // the host keeps failing: stop probing it
			}
			if isUnreachable(err) {
				return StateUnknown, "unreachable"
			}
			return StateUnknown, "error"
		}
	}
	h.errors.Store(0)
	return StateFiltered, "no-response" // never CLOSED without evidence
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded)
}

// bucket paces the probes at a rate per second (token bucket of one token).
type bucket struct {
	ticker *time.Ticker
}

func newBucket(perSecond int) *bucket {
	return &bucket{ticker: time.NewTicker(time.Second / time.Duration(max(1, perSecond)))}
}

func (b *bucket) wait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-b.ticker.C:
		return true
	}
}

func (b *bucket) stop() { b.ticker.Stop() }
