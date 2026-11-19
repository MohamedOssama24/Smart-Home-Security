package portscan

// [MOCK] services on the loopback interface: they simulate devices (SSH, Telnet, FTP, HTTP,
// HTTPS, RTSP, SMB, IPP, MQTT and the UDP protocols). No packet leaves this host. Every
// mock records what the agent sent, so that the policy tests can prove that no forbidden
// request (login, credential, stream, exploit, community string, NTP monlist) is ever made.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var loopback = netip.MustParseAddr("127.0.0.1")

func onlyLoopback(ip netip.Addr) bool { return ip == loopback }

// tcpMock accepts connections, records the bytes received and runs serve on each one.
type tcpMock struct {
	port     int
	accepted atomic.Int32
	mu       sync.Mutex
	received []byte
}

func (m *tcpMock) record(b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.received = append(m.received, b...)
}

func (m *tcpMock) got() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte{}, m.received...)
}

// recorder wraps a connection so that everything read from it is recorded.
type recorder struct {
	net.Conn
	m *tcpMock
}

func (r recorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.m.record(b[:n])
	return n, err
}

func newTCPMock(t *testing.T, serve func(conn net.Conn)) *tcpMock {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	m := &tcpMock{port: l.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			m.accepted.Add(1)
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if serve != nil {
					serve(recorder{conn, m})
				} else {
					// silent service: drain what the client sends until it closes
					buf := make([]byte, 512)
					for {
						if _, err := (recorder{conn, m}).Read(buf); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	return m
}

// closedPort returns a loopback port with no listener.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func testLists(services map[int]string) Lists {
	l := Lists{Version: "test", Services: map[string]string{}}
	for port, name := range services {
		l.Services["tcp/"+strconv.Itoa(port)] = name
	}
	return l
}

func fastLimits() Limits {
	return Limits{RatePerSecond: 1000, Concurrency: 16, PerHostConcurrency: 4, PerHostRatePerSecond: 1000,
		Timeout: time.Second}
}

func TestEmbeddedListsAreValid(t *testing.T) {
	quick, ok := DefaultLists.Profile("QUICK")
	if !ok || len(quick.TCP) < 30 || len(quick.TCP) > 60 || len(quick.UDP) == 0 {
		t.Fatalf("QUICK: %d TCP ports", len(quick.TCP))
	}
	standard, ok := DefaultLists.Profile("STANDARD")
	if !ok || len(standard.TCP) < 250 || len(standard.TCP) > 350 {
		t.Fatalf("STANDARD: %d TCP ports", len(standard.TCP))
	}
	if DefaultLists.ServiceOf(TCP, 554) != "rtsp" || DefaultLists.ServiceOf(UDP, 161) != "snmp" {
		t.Fatal("service hints missing")
	}
	for name, data := range map[string]string{
		"udp port without a safe probe": `{"version":"x","profiles":{"P":{"tcp":[80],"udp":[69]}}}`,
		"unsorted":                      `{"version":"x","profiles":{"P":{"tcp":[443,80],"udp":[]}}}`,
		"duplicate":                     `{"version":"x","profiles":{"P":{"tcp":[80,80],"udp":[]}}}`,
		"out of range":                  `{"version":"x","profiles":{"P":{"tcp":[70000],"udp":[]}}}`,
	} {
		if _, err := load([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTCPStatesAndCoverage(t *testing.T) {
	open := newTCPMock(t, nil)
	closed := closedPort(t)
	results, sums, warnings := Run(context.Background(), []netip.Addr{loopback}, Options{
		Profile: Profile{TCP: []int{open.port, closed}}, Lists: testLists(map[int]string{open.port: "mqtt"}),
		Limits: fastLimits(), InScope: onlyLoopback,
	})
	if len(warnings) != 0 || len(sums) != 1 {
		t.Fatalf("warnings %v, summaries %v", warnings, sums)
	}
	if len(results) != 1 || results[0].Port != open.port || results[0].State != StateOpen || results[0].Reason != "syn-ack" {
		t.Fatalf("results %+v", results)
	}
	if s := sums[0].TCP; s.Probed != 2 || s.Open != 1 || s.Closed != 1 {
		t.Fatalf("counters %+v", s)
	}
	// MQTT: the open port is the only evidence, no CONNECT (or anything else) is sent
	if svc := results[0].Service; svc.Name != "mqtt" || svc.Status != StatusProbable || svc.Confidence != "LOW" {
		t.Fatalf("service %+v", svc)
	}
	time.Sleep(50 * time.Millisecond)
	if got := open.got(); len(got) != 0 {
		t.Fatalf("bytes sent to the MQTT port: %q", got)
	}
}

func TestTimeoutIsFilteredNeverClosed(t *testing.T) {
	var attempts atomic.Int32
	timeout := &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
	_, sums, _ := Run(context.Background(), []netip.Addr{loopback}, Options{
		Profile: Profile{TCP: []int{81}}, Lists: testLists(nil), Limits: fastLimits(), InScope: onlyLoopback,
		dialTCP: func(context.Context, string, string) (net.Conn, error) {
			attempts.Add(1)
			return nil, timeout
		},
	})
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 1 + 1 retry", attempts.Load())
	}
	if s := sums[0].TCP; s.Filtered != 1 || s.Closed != 0 {
		t.Fatalf("counters %+v", s)
	}
}

func TestHostThatKeepsFailingIsPaused(t *testing.T) {
	var attempts atomic.Int32
	ports := make([]int, 40)
	for i := range ports {
		ports[i] = 1000 + i
	}
	limits := fastLimits()
	limits.PerHostConcurrency = 1
	_, sums, warnings := Run(context.Background(), []netip.Addr{loopback}, Options{
		Profile: Profile{TCP: ports, UDP: []int{53}}, Lists: testLists(nil), Limits: limits, InScope: onlyLoopback,
		dialTCP: func(context.Context, string, string) (net.Conn, error) {
			attempts.Add(1)
			return nil, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", errors.New("no route"))}
		},
	})
	if !sums[0].Paused || len(warnings) != 1 || warnings[0] != WarnHostPaused {
		t.Fatalf("summary %+v warnings %v", sums[0], warnings)
	}
	if n := attempts.Load(); n != pauseAfterErrors {
		t.Fatalf("%d connections to a failing host, want %d", n, pauseAfterErrors)
	}
	if sums[0].UDP.Probed != 0 {
		t.Fatal("UDP probes sent to a paused host")
	}
}

func TestOutOfScopeHostIsNeverContacted(t *testing.T) {
	m := newTCPMock(t, nil)
	results, sums, warnings := Run(context.Background(), []netip.Addr{loopback}, Options{
		Profile: Profile{TCP: []int{m.port}, UDP: []int{53}}, Lists: testLists(nil), Limits: fastLimits(),
		InScope: func(netip.Addr) bool { return false },
	})
	time.Sleep(50 * time.Millisecond)
	if len(results) != 0 || len(sums) != 0 || m.accepted.Load() != 0 {
		t.Fatalf("out-of-scope host contacted: %d connections", m.accepted.Load())
	}
	if len(warnings) != 1 || warnings[0] != WarnOutOfScope {
		t.Fatalf("warnings %v", warnings)
	}
	// without a scope function nothing is scanned at all
	if r, _, w := Run(context.Background(), []netip.Addr{loopback}, Options{Profile: Profile{TCP: []int{m.port}}}); len(r) != 0 || len(w) != 1 {
		t.Fatal("scan without scope check")
	}
}

func TestRateLimitIsApplied(t *testing.T) {
	ports := make([]int, 12)
	for i := range ports {
		ports[i] = closedPort(t)
	}
	limits := fastLimits()
	limits.RatePerSecond = 20 // 12 connections need at least ~0.55 s
	start := time.Now()
	_, sums, _ := Run(context.Background(), []netip.Addr{loopback}, Options{
		Profile: Profile{TCP: ports}, Lists: testLists(nil), Limits: limits, InScope: onlyLoopback,
	})
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("12 connections in %v at 20/s", elapsed)
	}
	if sums[0].TCP.Probed != 12 {
		t.Fatalf("probed %d", sums[0].TCP.Probed)
	}
}

func TestCancellationStopsTheScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, warnings := Run(ctx, []netip.Addr{loopback}, Options{
		Profile: Profile{TCP: []int{closedPort(t)}}, Lists: testLists(nil), Limits: fastLimits(), InScope: onlyLoopback,
	})
	if len(warnings) != 1 || warnings[0] != WarnIncomplete {
		t.Fatalf("warnings %v", warnings)
	}
}

func TestRefusedErrorClassification(t *testing.T) {
	if !isRefused(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}) {
		t.Fatal("ECONNREFUSED not recognized")
	}
	if isRefused(errors.New("other")) || !isTimeout(&net.OpError{Err: os.ErrDeadlineExceeded}) {
		t.Fatal("classification")
	}
}
