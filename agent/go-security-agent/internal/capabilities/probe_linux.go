package capabilities

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const capNetRaw = 13 // bit of CAP_NET_RAW in the capability sets

// probe on Linux: raw sockets need root or CAP_NET_RAW (granted by the systemd unit as an
// ambient capability); without it ICMP may still work through unprivileged datagram sockets
// (net.ipv4.ping_group_range) and neighbours can be read from /proc/net/arp.
func probe() Report {
	raw := os.Geteuid() == 0 || hasEffectiveCapability(capNetRaw)
	r := Report{Privileged: raw, ARP: Unavailable, ICMP: Unavailable}

	if raw && canOpen(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP))) {
		r.ARP = Raw
	} else if f, err := os.Open("/proc/net/arp"); err == nil {
		f.Close()
		r.ARP = OSTable
	}

	switch {
	case raw && canOpen(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP):
		r.ICMP = Raw
	case canOpen(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP):
		r.ICMP = Unprivileged
	}
	return r
}

// canOpen creates and immediately closes a socket: nothing is sent.
func canOpen(domain, typ, proto int) bool {
	fd, err := syscall.Socket(domain, typ|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

// hasEffectiveCapability reads CapEff from /proc/self/status.
func hasEffectiveCapability(bit uint) bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		return err == nil && mask&(1<<bit) != 0
	}
	return false
}
