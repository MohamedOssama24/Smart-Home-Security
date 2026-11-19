package portscan

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The port lists of the scan profiles and the "probable service" of each known port are
// versioned data (portlists.json), not code: docs/08-PORT-SCANNING-SERVICES.md §1.
//
//go:embed portlists.json
var listsJSON []byte

// Profile is the list of ports one scan profile contacts.
type Profile struct {
	TCP []int `json:"tcp"`
	UDP []int `json:"udp"`
}

// Lists is the parsed data file.
type Lists struct {
	Version  string             `json:"version"`
	Profiles map[string]Profile `json:"profiles"`
	// Services maps "tcp/80" to the service usually found on that port (a hint only).
	Services map[string]string `json:"services"`
}

// maxTCPPorts bounds a profile (DEEP, 1-1024 + known ports, is not part of this version).
const maxTCPPorts = 1100

// DefaultLists are the embedded lists, validated when the agent starts.
var DefaultLists = mustLoad(listsJSON)

func mustLoad(data []byte) Lists {
	l, err := load(data)
	if err != nil {
		panic("portlists.json: " + err.Error())
	}
	return l
}

func load(data []byte) (Lists, error) {
	var l Lists
	if err := json.Unmarshal(data, &l); err != nil {
		return Lists{}, err
	}
	if l.Version == "" || len(l.Profiles) == 0 {
		return Lists{}, fmt.Errorf("no version or no profile")
	}
	for name, p := range l.Profiles {
		if len(p.TCP) == 0 || len(p.TCP) > maxTCPPorts {
			return Lists{}, fmt.Errorf("profile %s: invalid TCP list", name)
		}
		if err := sortedPorts(p.TCP); err != nil {
			return Lists{}, fmt.Errorf("profile %s tcp: %w", name, err)
		}
		if err := sortedPorts(p.UDP); err != nil {
			return Lists{}, fmt.Errorf("profile %s udp: %w", name, err)
		}
		for _, port := range p.UDP {
			// UDP is never swept: only ports with a protocol-specific probe are contacted
			if udpProbes[port] == nil {
				return Lists{}, fmt.Errorf("profile %s: no safe UDP probe for port %d", name, port)
			}
		}
	}
	for key := range l.Services {
		proto, port, ok := strings.Cut(key, "/")
		n, err := strconv.Atoi(port)
		if !ok || (proto != "tcp" && proto != "udp") || err != nil || n < 1 || n > 65535 {
			return Lists{}, fmt.Errorf("invalid service key %q", key)
		}
	}
	return l, nil
}

func sortedPorts(ports []int) error {
	if !sort.IntsAreSorted(ports) {
		return fmt.Errorf("ports not sorted")
	}
	for i, p := range ports {
		if p < 1 || p > 65535 || i > 0 && ports[i-1] == p {
			return fmt.Errorf("invalid or duplicate port %d", p)
		}
	}
	return nil
}

// Profile returns the port list of a scan profile.
func (l Lists) Profile(name string) (Profile, bool) {
	p, ok := l.Profiles[name]
	return p, ok
}

// ServiceOf is the service usually found on a port ("" when unknown).
func (l Lists) ServiceOf(protocol string, port int) string {
	return l.Services[strings.ToLower(protocol)+"/"+strconv.Itoa(port)]
}
