package capabilities

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestDetectReportsKnownValuesAndConsistentWarnings(t *testing.T) {
	r := Detect()
	valid := map[string]bool{Raw: true, Unprivileged: true, OSAPI: true, OSTable: true, Unavailable: true}
	if !valid[r.ARP] || !valid[r.ICMP] {
		t.Fatalf("unexpected values %+v", r)
	}
	if r.Warnings == nil {
		t.Fatal("warnings must be an empty list, not null, in JSON")
	}
	if got, want := fmt.Sprint(r.Warnings), fmt.Sprint(warnings(r)); got != want {
		t.Fatalf("warnings %s, want %s", got, want)
	}
}

func TestWarningsForReducedCapabilities(t *testing.T) {
	full := Report{ARP: Raw, ICMP: Raw}
	if w := warnings(full); len(w) != 0 {
		t.Fatalf("no warning expected, got %v", w)
	}
	limited := Report{ARP: OSTable, ICMP: Unavailable}
	if w := warnings(limited); fmt.Sprint(w) != fmt.Sprint([]string{WarnARPTableOnly, WarnICMPUnavailable}) {
		t.Fatalf("unexpected warnings %v", w)
	}
	if w := warnings(Report{ARP: Unavailable, ICMP: OSAPI}); fmt.Sprint(w) != fmt.Sprint([]string{WarnARPUnavailable}) {
		t.Fatalf("unexpected warnings %v", w)
	}
}

func TestUsableInterfacesSkipsDownLoopbackAndAddresslessOnes(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	_, lan, _ := net.ParseCIDR("192.168.1.10/24")
	lan.IP = net.ParseIP("192.168.1.10")
	_, v6, _ := net.ParseCIDR("fd00::10/64")
	v6.IP = net.ParseIP("fd00::10")
	_, lo, _ := net.ParseCIDR("127.0.0.1/8")
	lo.IP = net.ParseIP("127.0.0.1")
	addrs := map[string][]net.Addr{
		"wlan0": {v6, lan},
		"lo":    {lo},
		"eth1":  {},
		"down0": {lan},
		"bad0":  nil,
	}
	ifaces := []net.Interface{
		{Name: "wlan0", MTU: 1500, HardwareAddr: mac, Flags: net.FlagUp},
		{Name: "lo", MTU: 65536, Flags: net.FlagUp | net.FlagLoopback},
		{Name: "eth1", MTU: 1500, Flags: net.FlagUp},
		{Name: "down0", MTU: 1500},
		{Name: "bad0", MTU: 1500, Flags: net.FlagUp},
	}
	got := usable(ifaces, func(i net.Interface) ([]net.Addr, error) {
		if i.Name == "bad0" {
			return nil, errors.New("boom")
		}
		return addrs[i.Name], nil
	})
	if len(got) != 1 {
		t.Fatalf("expected only wlan0, got %+v", got)
	}
	w := got[0]
	if w.Name != "wlan0" || w.MAC != "aa:bb:cc:dd:ee:ff" || w.MTU != 1500 ||
		fmt.Sprint(w.Addresses) != "[192.168.1.10/24 fd00::10/64]" {
		t.Fatalf("unexpected interface %+v", w)
	}
}

func TestHashChangesOnlyWithTheList(t *testing.T) {
	a := []Interface{{Name: "eth0", MTU: 1500, Addresses: []string{"192.168.1.2/24"}}}
	b := []Interface{{Name: "eth0", MTU: 1500, Addresses: []string{"192.168.1.2/24"}}}
	c := []Interface{{Name: "eth0", MTU: 1500, Addresses: []string{"192.168.1.3/24"}}}
	if Hash(a) != Hash(b) || Hash(a) == Hash(c) || len(Hash(a)) != 64 {
		t.Fatal("hash must be stable and depend on the content")
	}
}

func TestEqual(t *testing.T) {
	a := Report{ARP: OSTable, ICMP: Raw, Warnings: []string{WarnARPTableOnly}}
	b := Report{ARP: OSTable, ICMP: Raw, Warnings: []string{WarnARPTableOnly}}
	if !Equal(a, b) {
		t.Fatal("equal reports")
	}
	b.Privileged = true
	if Equal(a, b) {
		t.Fatal("different privilege")
	}
}

func TestInterfacesOfThisHost(t *testing.T) {
	list, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range list {
		if i.Name == "" || len(i.Addresses) == 0 || len(i.Addresses) > MaxAddresses {
			t.Fatalf("invalid interface %+v", i)
		}
	}
}
