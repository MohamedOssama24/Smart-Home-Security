package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Unicast mDNS (RFC 6762 §5.5, M23): hosts already found that did not answer the multicast
// query are asked directly on their port 5353 for the name they give themselves (reverse PTR
// in .local) and for their DNS-SD services. Many phones, computers and IoT devices answer a
// direct question even when multicast is filtered. Only IPv4 hosts of the authorized target,
// at most maxMDNSUnicast, are asked; only answers from the addresses asked are accepted.

const (
	maxMDNSUnicast = 256
	mdnsUnicastGap = 2 * time.Millisecond
)

func queryMDNSUnicast(ctx context.Context, n Network, hosts []netip.Addr, emit func(Observation)) []string {
	var targets []netip.Addr
	for _, h := range hosts {
		if h.Is4() && n.Target.Contains(h) && len(targets) < maxMDNSUnicast {
			targets = append(targets, h)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: n.Local.AsSlice()})
	if err != nil {
		return []string{WarnMDNSUnavailable}
	}
	defer conn.Close()
	for _, o := range mdnsUnicastExchange(ctx, conn, targets, 5353, mdnsRound) {
		emit(o)
	}
	return nil
}

// mdnsUnicastExchange: round 1 asks each target its reverse name and service types, round 2
// asks the hosts that declared services for their instances (port, TXT).
func mdnsUnicastExchange(ctx context.Context, conn net.PacketConn, targets []netip.Addr, port int,
	round time.Duration) []Observation {
	acc := &mdnsAnswers{types: map[string]bool{}, hosts: map[netip.Addr]*mdnsHost{}}
	send := func(ip netip.Addr, names []string) {
		if q, err := mdnsQuery(names); err == nil {
			_, _ = conn.WriteTo(q, &net.UDPAddr{IP: ip.AsSlice(), Port: port})
		}
	}
	for _, ip := range targets {
		if ctx.Err() != nil {
			break
		}
		send(ip, []string{reverseName(ip), "_services._dns-sd._udp.local."})
		time.Sleep(mdnsUnicastGap)
	}
	readMDNS(ctx, conn, round, acc)

	// types are collected for all responders together: ask each responder for them
	acc.mu.Lock()
	types := []string{"_device-info._tcp.local."}
	for t := range acc.types {
		if len(types) < maxMDNSServices {
			types = append(types, t)
		}
	}
	responders := make([]netip.Addr, 0, len(acc.hosts))
	for ip := range acc.hosts {
		responders = append(responders, ip)
	}
	acc.mu.Unlock()
	sort.Strings(types[1:])
	if len(types) > 1 && ctx.Err() == nil {
		for _, ip := range responders {
			send(ip, types)
		}
		readMDNS(ctx, conn, round, acc)
	}

	asked := make(map[netip.Addr]bool, len(targets))
	for _, t := range targets {
		asked[t] = true
	}
	var out []Observation
	for _, o := range acc.observations() {
		// answers from addresses not asked are dropped, as are the other addresses a host
		// declares for itself (only what was asked is attributed)
		if asked[o.IP] && o.Details["declaredBy"] == nil {
			out = append(out, o)
		}
	}
	return out
}

// reverseName is the reverse lookup name of an IPv4 address ("4.3.2.1.in-addr.arpa.").
func reverseName(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
}
