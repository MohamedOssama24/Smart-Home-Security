package discovery

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = iphlpapi.NewProc("IcmpSendEcho2Ex")
)

var iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

// icmpEchoReply is ICMP_ECHO_REPLY (same layout as the C structure on 32 and 64 bits).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	TTL           uint8
	TOS           uint8
	Flags         uint8
	OptionsSize   uint8
	OptionsData   uintptr
}

const (
	icmpTimeoutMs = 1000
	icmpRetries   = 1
)

// pingSweep on Windows sends ICMP echo requests with IcmpSendEcho2Ex (IP Helper API, no
// administrator rights), from the local address of the network: 1 echo per host, timeout
// 1 s, 1 retry. The TTL of the reply is reported (a weak hint for the OS later). No answer
// does not mean offline: firewalls often drop echo requests.
func pingSweep(ctx context.Context, n Network, o Options, found func(netip.Addr, int), probed func()) []string {
	if procIcmpSendEcho2Ex.Find() != nil {
		probedAll(n, probed)
		return []string{WarnICMPUnavailable}
	}
	pace := newLimiter(o.RatePerSecond)
	defer pace.stop()
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	failed := false
	var mu sync.Mutex
	for range max(1, o.Concurrency) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, _, _ := procIcmpCreateFile.Call()
			if windows.Handle(h) == windows.InvalidHandle {
				mu.Lock()
				failed = true
				mu.Unlock()
				for range jobs {
					probed()
				}
				return
			}
			defer procIcmpCloseHandle.Call(h)
			for host := range jobs {
				for attempt := 0; attempt <= icmpRetries && ctx.Err() == nil; attempt++ {
					if ttl, ok := echo(h, n.Local, host); ok {
						found(host, ttl)
						break
					}
				}
				probed()
			}
		}()
	}
	for _, host := range n.Hosts {
		if !pace.wait(ctx) {
			break
		}
		jobs <- host
	}
	close(jobs)
	wg.Wait()
	if failed {
		return []string{WarnICMPUnavailable}
	}
	return nil
}

func echo(h uintptr, src, dst netip.Addr) (int, bool) {
	s, d := src.As4(), dst.As4()
	payload := []byte("shsc-discovery")
	var buf [256]byte
	r, _, _ := procIcmpSendEcho2Ex.Call(h, 0, 0, 0,
		uintptr(binary.LittleEndian.Uint32(s[:])), uintptr(binary.LittleEndian.Uint32(d[:])),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), icmpTimeoutMs)
	if r == 0 {
		return 0, false
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
	if reply.Status != 0 || reply.Address != binary.LittleEndian.Uint32(d[:]) {
		return 0, false
	}
	return int(reply.TTL), true
}
