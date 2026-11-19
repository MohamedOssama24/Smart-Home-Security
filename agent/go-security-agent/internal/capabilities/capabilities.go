// Package capabilities is the self-diagnosis of the agent: which local network techniques
// this process can use with its current privileges, and which network interfaces the host
// has. Detection only opens and immediately closes local sockets or handles; it never
// sends a packet on the network.
//
// A technique that is not available is reported explicitly with a warning code, so that the
// dashboard can show reduced coverage instead of failing silently (docs/03-AGENT-PROTOCOL.md §10).
package capabilities

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"slices"
	"sort"
)

// Values of ARP and ICMP.
const (
	Raw          = "raw"          // raw sockets (needs root or CAP_NET_RAW)
	Unprivileged = "unprivileged" // ICMP datagram sockets allowed to unprivileged users
	OSAPI        = "os_api"       // operating system API (Windows iphlpapi)
	OSTable      = "os_table"     // only the neighbour table kept by the OS can be read
	Unavailable  = "unavailable"
)

// Warning codes (translated by the dashboard).
const (
	WarnARPTableOnly    = "ARP_TABLE_ONLY"
	WarnARPUnavailable  = "ARP_UNAVAILABLE"
	WarnICMPUnavailable = "ICMP_UNAVAILABLE"
	WarnNoInterfaces    = "NO_USABLE_INTERFACE"
)

// Limits of the reported interface list.
const (
	MaxInterfaces = 32
	MaxAddresses  = 16
)

// Report is what the agent can do with its current privileges.
type Report struct {
	Privileged bool     `json:"privileged"`
	ARP        string   `json:"arp"`
	ICMP       string   `json:"icmp"`
	Warnings   []string `json:"warnings"`
	// RouterIntegrations lists the router integrations configured by the owner on this agent
	// ("TR064", "SNMP"); never their settings or credentials.
	RouterIntegrations []string `json:"routerIntegrations"`
}

// Interface is a usable network interface of the host (up, not loopback, with an address).
type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
}

// Detect probes the techniques available to this process.
func Detect() Report {
	r := probe()
	r.Warnings = warnings(r)
	r.RouterIntegrations = []string{}
	return r
}

func warnings(r Report) []string {
	w := []string{}
	switch r.ARP {
	case OSTable:
		w = append(w, WarnARPTableOnly)
	case Unavailable:
		w = append(w, WarnARPUnavailable)
	}
	if r.ICMP == Unavailable {
		w = append(w, WarnICMPUnavailable)
	}
	return w
}

// Interfaces lists the usable interfaces of the host, sorted by name.
func Interfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	return usable(ifaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() }), nil
}

func usable(ifaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error)) []Interface {
	out := []Interface{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		list, err := addrs(iface)
		if err != nil {
			continue
		}
		var cidrs []string
		for _, a := range list {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsUnspecified() {
				continue
			}
			cidrs = append(cidrs, ipnet.String())
			if len(cidrs) == MaxAddresses {
				break
			}
		}
		if len(cidrs) == 0 {
			continue
		}
		sort.Strings(cidrs)
		entry := Interface{Name: iface.Name, MTU: iface.MTU, Addresses: cidrs}
		if len(iface.HardwareAddr) > 0 {
			entry.MAC = iface.HardwareAddr.String()
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > MaxInterfaces {
		out = out[:MaxInterfaces]
	}
	return out
}

// Hash is a stable fingerprint of an interface list, used to send the full list only when
// it changed.
func Hash(ifaces []Interface) string {
	data, _ := json.Marshal(ifaces)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Equal reports whether two reports describe the same capabilities.
func Equal(a, b Report) bool {
	return a.Privileged == b.Privileged && a.ARP == b.ARP && a.ICMP == b.ICMP &&
		slices.Equal(a.Warnings, b.Warnings) && slices.Equal(a.RouterIntegrations, b.RouterIntegrations)
}
