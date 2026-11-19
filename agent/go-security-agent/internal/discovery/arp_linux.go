package discovery

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	etherTypeARP = 0x0806
	arpRequest   = 1
	arpReply     = 2
	frameLength  = 42 // Ethernet header (14) + ARP for IPv4 over Ethernet (28)
	// how long to keep listening for late replies after the last request
	replyGrace = 1500 * time.Millisecond
)

// resolveARP on Linux sends raw ARP requests on the interface (needs CAP_NET_RAW, granted
// to the service by the systemd unit). Without the capability it falls back to reading the
// neighbour table kept by the kernel: no packet is sent, only hosts that recently talked
// with this machine are found (warning ARP_TABLE_ONLY).
func resolveARP(ctx context.Context, n Network, o Options, found func(netip.Addr, net.HardwareAddr),
	probed func()) []string {
	if len(n.Interface.MAC) != 6 {
		probedAll(n, probed)
		return []string{WarnInterfaceWithoutARP}
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(etherTypeARP)))
	if err != nil {
		f, openErr := os.Open("/proc/net/arp")
		if openErr != nil {
			probedAll(n, probed)
			return []string{WarnARPUnavailable}
		}
		defer f.Close()
		readNeighbourTable(f, n.Interface.Name, found)
		probedAll(n, probed)
		return []string{WarnARPTableOnly}
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(etherTypeARP), Ifindex: n.Interface.Index}); err != nil {
		probedAll(n, probed)
		return []string{WarnARPError}
	}
	timeout := syscall.NsecToTimeval((200 * time.Millisecond).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)

	stop := make(chan struct{})
	var wg sync.WaitGroup
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
			size, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				continue // timeout: check stop again
			}
			if ip, mac, ok := parseReply(buf[:size]); ok {
				found(ip, mac)
			}
		}
	}()

	local := n.Local.As4()
	to := &syscall.SockaddrLinklayer{Protocol: htons(etherTypeARP), Ifindex: n.Interface.Index, Halen: 6}
	copy(to.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	pace := newLimiter(o.RatePerSecond)
	failed := false
	for _, host := range n.Hosts {
		if !pace.wait(ctx) {
			break
		}
		if err := syscall.Sendto(fd, requestFrame(n.Interface.MAC, local, host.As4()), 0, to); err != nil {
			failed = true
		}
		probed()
	}
	pace.stop()
	select {
	case <-ctx.Done():
	case <-time.After(replyGrace):
	}
	close(stop)
	wg.Wait()
	if failed {
		return []string{WarnARPError}
	}
	return nil
}

// requestFrame builds a broadcast "who-has target tell local" ARP request.
func requestFrame(srcMAC net.HardwareAddr, local, target [4]byte) []byte {
	f := make([]byte, frameLength)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], srcMAC)
	f[12], f[13] = etherTypeARP>>8, etherTypeARP&0xff
	f[14], f[15] = 0, 1       // hardware type: Ethernet
	f[16], f[17] = 0x08, 0x00 // protocol type: IPv4
	f[18], f[19] = 6, 4       // address lengths
	f[20], f[21] = 0, arpRequest
	copy(f[22:28], srcMAC)
	copy(f[28:32], local[:])
	// target hardware address (32:38) stays zero
	copy(f[38:42], target[:])
	return f
}

// parseReply extracts sender IP and MAC from an ARP reply frame.
func parseReply(f []byte) (netip.Addr, net.HardwareAddr, bool) {
	if len(f) < frameLength || int(f[12])<<8|int(f[13]) != etherTypeARP {
		return netip.Addr{}, nil, false
	}
	if f[14] != 0 || f[15] != 1 || f[16] != 0x08 || f[17] != 0 || f[18] != 6 || f[19] != 4 ||
		f[20] != 0 || f[21] != arpReply {
		return netip.Addr{}, nil, false
	}
	ip := netip.AddrFrom4([4]byte(f[28:32]))
	return ip, net.HardwareAddr(append([]byte{}, f[22:28]...)), true
}

// readNeighbourTable reads /proc/net/arp; only complete entries (flag 0x2) of the interface.
func readNeighbourTable(r io.Reader, iface string, found func(netip.Addr, net.HardwareAddr)) {
	s := bufio.NewScanner(r)
	s.Scan() // header
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 6 || fields[5] != iface {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		mac, macErr := net.ParseMAC(fields[3])
		if err == nil && macErr == nil {
			found(ip, mac)
		}
	}
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
