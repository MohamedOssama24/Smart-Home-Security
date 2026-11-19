//go:build !windows

package discovery

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const icmpReplyGrace = time.Second

// pingSweep on Linux and macOS sends ICMP echo requests from the local address of the
// network: through an unprivileged ICMP datagram socket when the system allows it
// (net.ipv4.ping_group_range on Linux, always on macOS), otherwise through a raw socket
// (root or CAP_NET_RAW). 1 echo per host, then 1 retry for the hosts that did not answer.
// The TTL of the reply is reported. No answer does not mean offline.
func pingSweep(ctx context.Context, n Network, o Options, found func(netip.Addr, int), probed func()) []string {
	conn, raw, err := listenICMP(n.Local)
	if err != nil {
		probedAll(n, probed)
		return []string{WarnICMPUnavailable}
	}
	defer conn.Close()
	p := conn.IPv4PacketConn()
	_ = p.SetControlMessage(ipv4.FlagTTL, true)
	id := os.Getpid() & 0xffff

	var (
		mu      sync.Mutex
		replied = map[netip.Addr]bool{}
		wanted  = wantedHosts(n)
		stop    = make(chan struct{})
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			size, cm, peer, err := p.ReadFrom(buf)
			if err != nil {
				continue
			}
			ip, ok := peerAddr(peer)
			if !ok || !wanted[ip] {
				continue
			}
			ttl, echoID, ok := parseEchoReply(buf[:size], cm)
			if !ok || raw && echoID != id { // datagram sockets: the kernel already filters
				continue
			}
			mu.Lock()
			first := !replied[ip]
			replied[ip] = true
			mu.Unlock()
			if first {
				found(ip, ttl)
			}
		}
	}()

	pace := newLimiter(o.RatePerSecond)
	send := func(hosts []netip.Addr, report bool) {
		for i, host := range hosts {
			if !pace.wait(ctx) {
				return
			}
			msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: i & 0xffff,
				Data: []byte("shsc-discovery")}}
			if data, err := msg.Marshal(nil); err == nil {
				_, _ = conn.WriteTo(data, destination(host, raw))
			}
			if report {
				probed()
			}
		}
	}
	send(n.Hosts, true)
	sleep(ctx, icmpReplyGrace)
	var retry []netip.Addr
	mu.Lock()
	for _, h := range n.Hosts {
		if !replied[h] {
			retry = append(retry, h)
		}
	}
	mu.Unlock()
	send(retry, false)
	sleep(ctx, icmpReplyGrace)
	pace.stop()
	close(stop)
	wg.Wait()
	return nil
}

// listenICMP opens an unprivileged ICMP socket, or a raw one, bound to the local address.
func listenICMP(local netip.Addr) (*icmp.PacketConn, bool, error) {
	if c, err := icmp.ListenPacket("udp4", local.String()); err == nil {
		return c, false, nil
	}
	c, err := icmp.ListenPacket("ip4:icmp", local.String())
	return c, true, err
}

func destination(host netip.Addr, raw bool) net.Addr {
	if raw {
		return &net.IPAddr{IP: host.AsSlice()}
	}
	return &net.UDPAddr{IP: host.AsSlice()}
}

// parseEchoReply decodes an echo reply; some systems (macOS datagram sockets) deliver it
// with the IPv4 header, whose TTL is then used.
func parseEchoReply(b []byte, cm *ipv4.ControlMessage) (ttl, id int, ok bool) {
	if cm != nil {
		ttl = cm.TTL
	}
	if len(b) >= 20 && b[0]>>4 == 4 {
		header := int(b[0]&0x0f) * 4
		if len(b) < header {
			return 0, 0, false
		}
		ttl = int(b[8])
		b = b[header:]
	}
	m, err := icmp.ParseMessage(1, b)
	if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
		return 0, 0, false
	}
	e, isEcho := m.Body.(*icmp.Echo)
	if !isEcho {
		return 0, 0, false
	}
	return ttl, e.ID, true
}
