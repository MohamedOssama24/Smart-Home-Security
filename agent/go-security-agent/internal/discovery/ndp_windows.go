package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetIpNetTable2 = iphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable   = iphlpapi.NewProc("FreeMibTable")
)

// MIB_IPNET_ROW2 layout (netioapi.h): SOCKADDR_INET (28 bytes), InterfaceIndex at 28,
// InterfaceLuid at 32, PhysicalAddress[32] at 40, PhysicalAddressLength at 72, State at 76.
const (
	ipnetRowSize     = 88
	ipnetTableOffset = 8
	nlnsProbe        = 2 // Probe, Delay, Stale, Reachable and Permanent entries are kept
)

// echoAllNodes is not used on Windows (no unprivileged ICMPv6 socket): table only.
func echoAllNodes(context.Context, Network) ([]netip.Addr, error) {
	return nil, errors.New("all-nodes echo not supported on Windows")
}

// neighbourTable6 reads the IPv6 neighbour table of the interface (GetIpNetTable2).
func neighbourTable6(ifIndex int) ([]neighbour, error) {
	if err := procGetIpNetTable2.Find(); err != nil {
		return nil, err
	}
	var table unsafe.Pointer
	if r, _, _ := procGetIpNetTable2.Call(uintptr(windows.AF_INET6), uintptr(unsafe.Pointer(&table))); r != 0 {
		return nil, windows.Errno(r)
	}
	defer procFreeMibTable.Call(uintptr(table))
	count := int(*(*uint32)(table))
	rows := unsafe.Slice((*byte)(unsafe.Add(table, ipnetTableOffset)), count*ipnetRowSize)
	var out []neighbour
	for i := range count {
		if nb, ok := parseIpnetRow(rows[i*ipnetRowSize:(i+1)*ipnetRowSize], ifIndex); ok {
			out = append(out, nb)
		}
	}
	return out, nil
}

func parseIpnetRow(r []byte, ifIndex int) (neighbour, bool) {
	le := binary.LittleEndian
	if le.Uint16(r[0:]) != windows.AF_INET6 || int(le.Uint32(r[28:])) != ifIndex || le.Uint32(r[76:]) < nlnsProbe {
		return neighbour{}, false
	}
	nb := neighbour{ip: netip.AddrFrom16([16]byte(r[8:24]))}
	if l := le.Uint32(r[72:]); l > 0 && l <= 32 {
		nb.mac = net.HardwareAddr(append([]byte{}, r[40:40+l]...))
	}
	return nb, true
}
