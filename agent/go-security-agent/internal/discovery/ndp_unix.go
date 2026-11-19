//go:build !windows

package discovery

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var allNodes = netip.MustParseAddr("ff02::1")

// echoAllNodes sends one echo request to ff02::1 on the interface of the network, from the
// local address of the network, and collects the replies for one second.
func echoAllNodes(ctx context.Context, n Network) ([]netip.Addr, error) {
	conn, raw, err := listenICMPv6(n.Local)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	p := conn.IPv6PacketConn()
	_ = p.SetMulticastInterface(&net.Interface{Index: n.Interface.Index, Name: n.Interface.Name})
	_ = p.SetMulticastHopLimit(1)
	_ = p.SetMulticastLoopback(false)
	id := os.Getpid() & 0xffff
	msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("shsc-discovery")}}
	data, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}
	var dst net.Addr = &net.UDPAddr{IP: allNodes.AsSlice(), Zone: n.Interface.Name}
	if raw {
		dst = &net.IPAddr{IP: allNodes.AsSlice(), Zone: n.Interface.Name}
	}
	if _, err := conn.WriteTo(data, dst); err != nil {
		return nil, err
	}
	return collectEchoReplies(ctx, conn, raw, id, time.Second), nil
}

// collectEchoReplies reads ICMPv6 echo replies (one per source) during window.
func collectEchoReplies(ctx context.Context, conn net.PacketConn, raw bool, id int, window time.Duration) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	deadline := time.Now().Add(window)
	buf := make([]byte, 1500)
	for ctx.Err() == nil && time.Now().Before(deadline) && len(out) < maxNameLookups {
		_ = conn.SetReadDeadline(minTime(deadline, time.Now().Add(200*time.Millisecond)))
		size, from, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		ip, ok := peerAddr(from)
		if !ok || seen[ip] {
			continue
		}
		m, err := icmp.ParseMessage(58, buf[:size])
		if err != nil || m.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		if e, isEcho := m.Body.(*icmp.Echo); !isEcho || raw && e.ID != id {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

func listenICMPv6(local netip.Addr) (*icmp.PacketConn, bool, error) {
	if c, err := icmp.ListenPacket("udp6", local.String()); err == nil {
		return c, false, nil
	}
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", local.String())
	return c, true, err
}
