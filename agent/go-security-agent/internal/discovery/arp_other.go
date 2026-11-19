//go:build !windows && !linux

package discovery

import (
	"context"
	"net"
	"net/netip"
)

// resolveARP: active ARP is not implemented on this platform yet (macOS needs BPF); the
// scan reports it instead of failing silently.
func resolveARP(_ context.Context, n Network, _ Options, _ func(netip.Addr, net.HardwareAddr), probed func()) []string {
	for range n.Hosts {
		probed()
	}
	return []string{WarnARPUnavailable}
}
