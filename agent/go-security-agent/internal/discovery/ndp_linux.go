package discovery

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
)

const (
	ndaDst    = 1
	ndaLLAddr = 2
	// NUD states kept: REACHABLE, STALE, DELAY, PROBE, NOARP, PERMANENT
	nudValid = 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80
)

// neighbourTable6 reads the IPv6 neighbours of the interface through netlink (RTM_GETNEIGH,
// read-only, no privilege needed).
func neighbourTable6(ifIndex int) ([]neighbour, error) {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET6)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	var out []neighbour
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH {
			continue
		}
		if nb, ok := parseNeighMsg(m.Data, ifIndex); ok {
			out = append(out, nb)
		}
	}
	return out, nil
}

// parseNeighMsg decodes an ndmsg (12 bytes) and its NDA_DST / NDA_LLADDR attributes.
func parseNeighMsg(b []byte, ifIndex int) (neighbour, bool) {
	if len(b) < 12 || b[0] != syscall.AF_INET6 ||
		int(int32(binary.NativeEndian.Uint32(b[4:]))) != ifIndex ||
		binary.NativeEndian.Uint16(b[8:])&nudValid == 0 {
		return neighbour{}, false
	}
	var nb neighbour
	for i := 12; i+4 <= len(b); {
		l := int(binary.NativeEndian.Uint16(b[i:]))
		t := binary.NativeEndian.Uint16(b[i+2:])
		if l < 4 || i+l > len(b) {
			break
		}
		v := b[i+4 : i+l]
		switch t {
		case ndaDst:
			if ip, ok := netip.AddrFromSlice(v); ok {
				nb.ip = ip
			}
		case ndaLLAddr:
			nb.mac = net.HardwareAddr(append([]byte{}, v...))
		}
		i += (l + 3) &^ 3
	}
	return nb, nb.ip.Is6()
}
