package discovery

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

func TestParseNeighMsgKeepsUsableEntriesOfTheInterface(t *testing.T) {
	msg := func(ifIndex int32, state uint16) []byte {
		b := make([]byte, 12)
		b[0] = syscall.AF_INET6
		binary.NativeEndian.PutUint32(b[4:], uint32(ifIndex))
		binary.NativeEndian.PutUint16(b[8:], state)
		attr := func(typ uint16, v []byte) {
			a := make([]byte, 4)
			binary.NativeEndian.PutUint16(a, uint16(4+len(v)))
			binary.NativeEndian.PutUint16(a[2:], typ)
			a = append(a, v...)
			for len(a)%4 != 0 {
				a = append(a, 0)
			}
			b = append(b, a...)
		}
		ip := netip.MustParseAddr("fd00::30").As16()
		attr(ndaDst, ip[:])
		attr(ndaLLAddr, []byte{0xaa, 0xbb, 0xcc, 0, 0, 0x30})
		return b
	}
	nb, ok := parseNeighMsg(msg(2, 0x02), 2)
	if !ok || nb.ip.String() != "fd00::30" || nb.mac.String() != "aa:bb:cc:00:00:30" {
		t.Fatalf("%+v %v", nb, ok)
	}
	if _, ok := parseNeighMsg(msg(3, 0x02), 2); ok {
		t.Fatal("entry of another interface accepted")
	}
	if _, ok := parseNeighMsg(msg(2, 0x20), 2); ok { // NUD_FAILED
		t.Fatal("failed entry accepted")
	}
}
