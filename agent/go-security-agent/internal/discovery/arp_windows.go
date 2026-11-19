package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"unsafe"
)

var procSendARP = iphlpapi.NewProc("SendARP")

// resolveARP on Windows sends one ARP request per host through SendARP (IP Helper API):
// the operating system resolves the address on the interface that owns the source address
// and returns the MAC address, or an error when nobody answers.
func resolveARP(ctx context.Context, n Network, o Options, found func(netip.Addr, net.HardwareAddr),
	probed func()) []string {
	if err := procSendARP.Find(); err != nil {
		for range n.Hosts {
			probed()
		}
		return []string{WarnARPUnavailable}
	}
	if len(n.Interface.MAC) != 6 {
		for range n.Hosts {
			probed()
		}
		return []string{WarnInterfaceWithoutARP}
	}
	pace := newLimiter(o.RatePerSecond)
	defer pace.stop()
	slots := make(chan struct{}, max(1, o.Concurrency))
	var wg sync.WaitGroup
	for _, host := range n.Hosts {
		if !pace.wait(ctx) {
			break
		}
		slots <- struct{}{}
		wg.Add(1)
		go func(host netip.Addr) {
			defer func() { <-slots; wg.Done(); probed() }()
			if mac, ok := sendARP(host, n.Local); ok {
				found(host, mac)
			}
		}(host)
	}
	wg.Wait()
	return nil
}

// sendARP returns the MAC address of dst, asked from the local address src.
func sendARP(dst, src netip.Addr) (net.HardwareAddr, bool) {
	d, s := dst.As4(), src.As4()
	var mac [8]byte
	size := uint32(len(mac))
	// IPAddr values are in network byte order: the in-memory layout of the 4 bytes
	r, _, _ := procSendARP.Call(uintptr(binary.LittleEndian.Uint32(d[:])), uintptr(binary.LittleEndian.Uint32(s[:])),
		uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 || size != 6 {
		return nil, false
	}
	return net.HardwareAddr(append([]byte{}, mac[:6]...)), true
}
