package discovery

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// M23: a device whose answer to the multicast search is lost (host firewall) is asked directly:
// the unicast M-SEARCH names the device in HOST, the answer leads to the description and the icon.
// [MOCK] device on loopback.
func TestUnicastSearchReachesTheDeviceAndFetchesItsIcon(t *testing.T) {
	var fetched atomic.Int32
	srv := mockIconDevice(t, false, &fetched)
	var host atomic.Value
	dst := udpResponder(t, func(q []byte) [][]byte {
		s := string(q)
		if !strings.HasPrefix(s, "M-SEARCH * HTTP/1.1") || strings.Contains(s, "MX:") {
			return nil
		}
		for _, line := range strings.Split(s, "\r\n") {
			if strings.HasPrefix(line, "HOST: ") {
				host.Store(strings.TrimPrefix(line, "HOST: "))
			}
		}
		return [][]byte{[]byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: " + srv.URL + "/desc.xml\r\n\r\n")}
	})
	target := dst.AddrPort()
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	obs := ssdpUnicastExchange(context.Background(), clientConn(t), []netip.AddrPort{target}, 400*time.Millisecond,
		netip.Addr.IsLoopback)
	if len(obs) != 1 || obs[0].Method != MethodSSDP || obs[0].Details["friendlyName"] != "MOCK TV" {
		t.Fatalf("observations %+v", obs)
	}
	if host.Load() != target.String() {
		t.Fatalf("HOST header %v, want %s", host.Load(), target)
	}
	if obs[0].Icon == nil || obs[0].Icon.Width != 120 {
		t.Fatalf("icon %+v", obs[0].Icon)
	}
}

// Answers from addresses that were not asked, or outside the scope, are ignored.
func TestUnicastSearchAcceptsOnlyTheHostsAsked(t *testing.T) {
	dst := udpResponder(t, func([]byte) [][]byte {
		return [][]byte{[]byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: http://127.0.0.1:1/\r\n\r\n")}
	})
	target := netip.AddrPortFrom(dst.AddrPort().Addr().Unmap(), dst.AddrPort().Port())
	if obs := ssdpUnicastExchange(context.Background(), clientConn(t), []netip.AddrPort{target}, 300*time.Millisecond,
		func(netip.Addr) bool { return false }); len(obs) != 0 {
		t.Fatalf("out-of-scope answer accepted: %+v", obs)
	}
}

// Only IPv4 hosts inside the authorized target are asked, at most maxSSDPUnicast.
func TestUnicastSearchAsksOnlyHostsInTheTarget(t *testing.T) {
	n := Network{Target: netip.MustParsePrefix("192.0.2.0/24"), Local: netip.MustParseAddr("127.0.0.1")}
	var emitted int
	warn := searchSSDPUnicast(context.Background(), n, []netip.Addr{netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("fd00::1")}, func(Observation) { emitted++ })
	if warn != nil || emitted != 0 {
		t.Fatalf("hosts outside the target were asked: warn=%v emitted=%d", warn, emitted)
	}
}
