package capabilities

import (
	"os"
	"syscall"
)

// probe on macOS: raw ARP needs root to open a BPF device; ICMP datagram sockets are allowed
// to every user; without BPF the neighbour table of the OS can still be read.
func probe() Report {
	root := os.Geteuid() == 0
	r := Report{Privileged: root, ARP: OSTable, ICMP: Unavailable}

	if root {
		// opening a BPF device and closing it at once: no interface is attached, nothing is captured
		for _, dev := range []string{"/dev/bpf", "/dev/bpf0", "/dev/bpf1", "/dev/bpf2", "/dev/bpf3"} {
			if f, err := os.OpenFile(dev, os.O_RDWR, 0); err == nil {
				f.Close()
				r.ARP = Raw
				break
			}
		}
	}
	switch {
	case root && canOpen(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP):
		r.ICMP = Raw
	case canOpen(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP):
		r.ICMP = Unprivileged
	}
	return r
}

// canOpen creates and immediately closes a socket: nothing is sent.
func canOpen(domain, typ, proto int) bool {
	fd, err := syscall.Socket(domain, typ, proto)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}
