package discovery

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Host names of the hosts already found: NetBIOS node status (UDP 137, one unicast query per
// host) and reverse DNS through the resolver configured on this host.

const (
	netbiosGrace     = 1500 * time.Millisecond
	netbiosRate      = 50
	rdnsTimeout      = 1500 * time.Millisecond
	rdnsConcurrency  = 8
	maxNameLookups   = 256
	netbiosGroupFlag = 0x8000
)

// queryNetBIOS sends an NBSTAT query to each host and reads the names it declares.
func queryNetBIOS(ctx context.Context, n Network, hostList []netip.Addr, emit func(Observation)) []string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: n.Local.AsSlice()})
	if err != nil {
		return []string{WarnNetBIOSUnavailable}
	}
	defer conn.Close()
	netbiosExchange(ctx, conn, hostList, 137, emit)
	return nil
}

func netbiosExchange(ctx context.Context, conn net.PacketConn, hostList []netip.Addr, port int, emit func(Observation)) {
	if len(hostList) > maxNameLookups {
		hostList = hostList[:maxNameLookups]
	}
	id := uint16(rand.Uint32())
	wanted := map[netip.Addr]bool{}
	for _, h := range hostList {
		wanted[h] = true
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		seen := map[netip.Addr]bool{}
		buf := make([]byte, 1500)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			size, from, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			src, ok := peerAddr(from)
			if !ok || !wanted[src] || seen[src] {
				continue
			}
			if name, group, mac, ok := parseNodeStatus(buf[:size], id); ok && name != "" {
				seen[src] = true
				details := map[string]any{}
				if group != "" {
					details["workgroup"] = group
				}
				emit(Observation{IP: src, MAC: mac, Method: MethodNetBIOS, Hostname: name, Details: details})
			}
		}
	}()
	pace := newLimiter(netbiosRate)
	query := nodeStatusRequest(id)
	for _, h := range hostList {
		if !pace.wait(ctx) {
			break
		}
		_, _ = conn.WriteTo(query, &net.UDPAddr{IP: h.AsSlice(), Port: port})
	}
	pace.stop()
	sleep(ctx, netbiosGrace)
	close(stop)
	wg.Wait()
}

// nodeStatusRequest is an NBSTAT query for the wildcard name "*" (RFC 1002 §4.2.17).
func nodeStatusRequest(id uint16) []byte {
	b := make([]byte, 12, 50)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[4:], 1) // one question
	name := make([]byte, 16)
	name[0] = '*'
	b = append(b, 32)
	for _, c := range name { // first-level encoding: each half byte + 'A'
		b = append(b, 'A'+c>>4, 'A'+c&0x0f)
	}
	b = append(b, 0, 0x00, 0x21, 0x00, 0x01) // end of name, type NBSTAT, class IN
	return b
}

// parseNodeStatus returns the computer name (unique name, suffix 0x00), the workgroup
// (group name, suffix 0x00) and the MAC address of an NBSTAT answer.
func parseNodeStatus(b []byte, id uint16) (name, group, mac string, ok bool) {
	if len(b) < 12 || binary.BigEndian.Uint16(b[0:]) != id || b[2]&0x80 == 0 {
		return "", "", "", false
	}
	i := 12
	switch {
	case i < len(b) && b[i] == 32:
		i += 34
	case i+1 < len(b) && b[i]&0xc0 == 0xc0:
		i += 2
	default:
		return "", "", "", false
	}
	i += 10 // type, class, TTL, data length
	if i >= len(b) {
		return "", "", "", false
	}
	count := int(b[i])
	i++
	for k := 0; k < count; k++ {
		if i+18 > len(b) {
			return "", "", "", false
		}
		entry := strings.TrimRight(string(b[i:i+15]), " \x00")
		suffix, flags := b[i+15], binary.BigEndian.Uint16(b[i+16:])
		i += 18
		if suffix != 0x00 || !printable(entry) {
			continue
		}
		if flags&netbiosGroupFlag != 0 {
			if group == "" {
				group = entry
			}
		} else if name == "" {
			name = entry
		}
	}
	if i+6 <= len(b) {
		if hw := net.HardwareAddr(b[i : i+6]); !isZero(hw) {
			mac = hw.String()
		}
	}
	return name, group, mac, true
}

func printable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

// reverseDNS asks the configured resolver for the PTR name of each host.
func reverseDNS(ctx context.Context, hostList []netip.Addr, emit func(Observation)) {
	if len(hostList) > maxNameLookups {
		hostList = hostList[:maxNameLookups]
	}
	sem := make(chan struct{}, rdnsConcurrency)
	var wg sync.WaitGroup
	for _, h := range hostList {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			lookup, cancel := context.WithTimeout(ctx, rdnsTimeout)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(lookup, h.String())
			if err != nil || len(names) == 0 {
				return
			}
			if name := strings.TrimSuffix(names[0], "."); name != "" {
				emit(Observation{IP: h, Method: MethodRDNS, Hostname: truncate(name, 255)})
			}
		}()
	}
	wg.Wait()
}
