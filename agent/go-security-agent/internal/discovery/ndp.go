package discovery

import (
	"context"
	"net"
	"net/netip"
)

// IPv6 neighbours of a connected IPv6 target: one ICMPv6 echo to the all-nodes link-local
// group ff02::1, sent only on the interface of the target (Linux, macOS), then the neighbour
// table kept by the system (Linux, Windows). A /64 is never swept. Hosts that do not answer
// the echo and have not talked with this host are not found (declared limit).

type neighbour struct {
	ip  netip.Addr
	mac net.HardwareAddr
}

func discoverNDP(ctx context.Context, n Network, emit func(Observation)) []string {
	replies, echoErr := echoAllNodes(ctx, n)
	for _, ip := range replies {
		emit(Observation{IP: ip, Method: MethodNDP, Details: map[string]any{"echo": true}})
	}
	table, tableErr := neighbourTable6(n.Interface.Index)
	for _, nb := range table {
		emitNeighbour(n, nb, emit)
	}
	switch {
	case echoErr != nil && tableErr != nil:
		return []string{WarnNDPUnavailable}
	case echoErr != nil:
		return []string{WarnNDPTableOnly}
	}
	return nil
}

func emitNeighbour(n Network, nb neighbour, emit func(Observation)) {
	ip := nb.ip.WithZone("")
	if !n.Target.Contains(ip) {
		// a global address of a neighbour on the link of the target is only recorded next to the
		// in-scope observation with the same MAC (ADR-075): never probed, never resolved
		if isGlobal6(ip) && len(nb.mac) == 6 && !isZero(nb.mac) {
			emit(Observation{IP: ip, MAC: nb.mac.String(), Method: methodGlobalNeighbour})
		}
		return
	}
	o := Observation{IP: ip, Method: MethodNDP}
	if len(nb.mac) == 6 && !isZero(nb.mac) {
		o.MAC = nb.mac.String()
	}
	emit(o)
}

// global6 is the IPv6 global unicast range 2000::/3.
var global6 = netip.MustParsePrefix("2000::/3")

func isGlobal6(ip netip.Addr) bool {
	return ip.Is6() && !ip.Is4In6() && global6.Contains(ip)
}
