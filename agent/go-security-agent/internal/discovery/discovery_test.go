package discovery

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

func lan() []Interface {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	return []Interface{{Name: "eth0", Index: 2, MAC: mac,
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.50.2/24"), netip.MustParsePrefix("fd00::2/64")}}}
}

func TestPlanKeepsOnlyConnectedAuthorizedTargets(t *testing.T) {
	plan := MakePlan([]netip.Prefix{
		netip.MustParsePrefix("192.168.50.0/24"), // connected
		netip.MustParsePrefix("10.0.0.0/24"),     // not connected: never routed
		netip.MustParsePrefix("fd00::/64"),       // connected IPv6: no host list
	}, lan(), 1024)
	if len(plan.Networks) != 2 || plan.Networks[0].Interface.Name != "eth0" || !plan.Networks[1].IPv6() ||
		len(plan.Networks[1].Hosts) != 0 {
		t.Fatalf("unexpected networks %+v", plan.Networks)
	}
	hosts := plan.Networks[0].Hosts
	// .0 and .255 excluded, and the local address .2 is not probed
	if plan.TotalHosts != 253 || len(hosts) != 253 || slices.Contains(hosts, netip.MustParseAddr("192.168.50.2")) ||
		hosts[0] != netip.MustParseAddr("192.168.50.1") || hosts[252] != netip.MustParseAddr("192.168.50.254") {
		t.Fatalf("unexpected hosts: %d", len(hosts))
	}
	if !slices.Equal(plan.Warnings, []string{WarnTargetNotConnected}) {
		t.Fatalf("warnings = %v", plan.Warnings)
	}
	if !plan.InScope(netip.MustParseAddr("10.0.0.5")) || plan.InScope(netip.MustParseAddr("10.0.1.5")) {
		t.Fatal("scope must cover every authorized target and nothing else")
	}
}

func TestPlanRespectsTheHostLimit(t *testing.T) {
	plan := MakePlan([]netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}, lan(), 10)
	if plan.TotalHosts != 10 || !slices.Contains(plan.Warnings, WarnHostLimitReached) {
		t.Fatalf("total=%d warnings=%v", plan.TotalHosts, plan.Warnings)
	}
}

// fakeTechniques simulate the network: every method also reports addresses outside the
// authorized targets, which must never reach the result.
func fakeTechniques(netbiosHosts *[]netip.Addr, routerCalled *bool) *techniques {
	var mu sync.Mutex
	mac, _ := net.ParseMAC("aa:bb:cc:00:00:10")
	ip := netip.MustParseAddr
	return &techniques{
		arp: func(_ context.Context, n Network, _ Options, found func(netip.Addr, net.HardwareAddr), probed func()) []string {
			found(ip("192.168.50.10"), mac)
			found(ip("192.168.60.10"), mac)                                // other network: ignored
			found(ip("192.168.50.11"), net.HardwareAddr{0, 0, 0, 0, 0, 0}) // incomplete entry
			probedAll(n, probed)
			return nil
		},
		icmp: func(_ context.Context, n Network, _ Options, found func(netip.Addr, int), probed func()) []string {
			found(ip("192.168.50.10"), 64)
			found(ip("8.8.8.8"), 118)
			probedAll(n, probed)
			return []string{WarnICMPUnavailable}
		},
		mdns: func(_ context.Context, _ Network, emit func(Observation)) []string {
			emit(Observation{IP: ip("192.168.50.20"), Method: MethodMDNS, Hostname: "printer",
				Details: map[string]any{"selfDeclared": true}})
			emit(Observation{IP: ip("fd00::20"), Method: MethodMDNS, Hostname: "printer"})
			emit(Observation{IP: ip("fe80::20"), Method: MethodMDNS}) // link-local: not authorized
			return nil
		},
		ssdp: func(_ context.Context, _ Network, emit func(Observation)) []string {
			emit(Observation{IP: ip("192.168.50.1"), Method: MethodSSDP, Details: map[string]any{"big": strings.Repeat("x", 4000)}})
			emit(Observation{IP: ip("203.0.113.9"), Method: MethodSSDP})
			return nil
		},
		ssdpUni: func(_ context.Context, _ Network, hosts []netip.Addr, emit func(Observation)) []string {
			for _, h := range hosts {
				if h == ip("192.168.50.1") {
					panic("host that already answered SSDP asked again")
				}
			}
			emit(Observation{IP: ip("203.0.113.10"), Method: MethodSSDP}) // outside the targets: dropped
			return nil
		},
		mdnsUni: func(_ context.Context, _ Network, hosts []netip.Addr, emit func(Observation)) []string {
			for _, h := range hosts {
				if h == ip("192.168.50.20") {
					panic("host that already answered mDNS asked again")
				}
			}
			emit(Observation{IP: ip("203.0.113.11"), Method: MethodMDNS}) // outside the targets: dropped
			return nil
		},
		ndp: func(_ context.Context, _ Network, emit func(Observation)) []string {
			emit(Observation{IP: ip("fd00::30"), Method: MethodNDP, MAC: "aa:bb:cc:00:00:30"})
			emit(Observation{IP: ip("2001:db8::1"), Method: MethodNDP})
			// global neighbours (MOCK): attached to fd00::30 by MAC, or dropped without an in-scope MAC
			emit(Observation{IP: ip("2001:db8::30"), Method: methodGlobalNeighbour, MAC: "AA:BB:CC:00:00:30"})
			emit(Observation{IP: ip("2001:db8::99"), Method: methodGlobalNeighbour, MAC: "aa:bb:cc:00:00:99"})
			emit(Observation{IP: ip("fd00:1::5"), Method: methodGlobalNeighbour, MAC: "aa:bb:cc:00:00:30"})
			return []string{WarnNDPTableOnly}
		},
		netbios: func(_ context.Context, _ Network, hosts []netip.Addr, emit func(Observation)) []string {
			mu.Lock()
			*netbiosHosts = append(*netbiosHosts, hosts...)
			mu.Unlock()
			emit(Observation{IP: ip("192.168.50.10"), Method: MethodNetBIOS, Hostname: "DESKTOP-1"})
			return nil
		},
		rdns: func(_ context.Context, hosts []netip.Addr, emit func(Observation)) {
			for _, h := range hosts {
				emit(Observation{IP: h, Method: MethodRDNS, Hostname: "h-" + h.String()})
			}
		},
		router: func(_ context.Context, _ RouterConfig, inScope func(netip.Addr) bool, emit func(Observation)) []string {
			*routerCalled = true
			if inScope(ip("10.9.9.9")) {
				panic("scope function too permissive")
			}
			emit(Observation{IP: ip("192.168.50.40"), Method: MethodTR064, Hostname: "tv"})
			emit(Observation{IP: ip("10.9.9.9"), Method: MethodTR064})
			return nil
		},
	}
}

func TestRunMergesAllMethodsAndKeepsOnlyAuthorizedAddresses(t *testing.T) {
	var netbiosHosts []netip.Addr
	var routerCalled bool
	plan := MakePlan([]netip.Prefix{netip.MustParsePrefix("192.168.50.0/24"), netip.MustParsePrefix("fd00::/64")},
		lan(), 1024)
	var lastDone, lastTotal int
	var mu sync.Mutex
	obs, warnings := Run(context.Background(), plan, Options{RatePerSecond: 100, Router: &RouterConfig{Address: "192.168.50.1"},
		tech: fakeTechniques(&netbiosHosts, &routerCalled),
		Progress: func(done, total, _ int) {
			mu.Lock()
			lastDone, lastTotal = max(lastDone, done), total
			mu.Unlock()
		}})

	type key struct{ ip, method string }
	got := map[key]Observation{}
	for _, o := range obs {
		got[key{o.IP.String(), o.Method}] = o
		if !plan.InScope(o.IP) {
			t.Fatalf("observation outside the authorized targets: %+v", o)
		}
	}
	for _, k := range []key{{"192.168.50.2", MethodSelf}, {"fd00::2", MethodSelf}, {"192.168.50.10", MethodARP}, {"192.168.50.10", MethodICMP},
		{"192.168.50.20", MethodMDNS}, {"fd00::20", MethodMDNS}, {"192.168.50.1", MethodSSDP}, {"fd00::30", MethodNDP},
		{"192.168.50.40", MethodTR064}, {"192.168.50.10", MethodNetBIOS}, {"192.168.50.10", MethodRDNS}} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %v", k)
		}
	}
	if len(obs) != 11+5 { // + reverse DNS of the other hosts found (.1, .20, .40, fd00::20, fd00::30)
		t.Errorf("unexpected observation count %d: %+v", len(obs), obs)
	}
	if g := got[key{"fd00::30", MethodNDP}].Details[DetailGlobalIPv6]; !slices.Equal(g.([]string), []string{"2001:db8::30"}) {
		t.Errorf("global IPv6 of fd00::30: %v", g)
	}
	if got[key{"fd00::20", MethodMDNS}].Details[DetailGlobalIPv6] != nil {
		t.Error("global IPv6 attached without a MAC")
	}
	if got[key{"192.168.50.10", MethodICMP}].Details["ttl"] != 64 || got[key{"192.168.50.20", MethodMDNS}].Hostname != "printer" {
		t.Error("details or hostname lost")
	}
	if d := got[key{"192.168.50.1", MethodSSDP}].Details; d["truncated"] != true || len(d) != 1 {
		t.Errorf("oversized details must be truncated, got %v", d)
	}
	if !routerCalled || !slices.Equal(warnings, []string{WarnICMPUnavailable, WarnNDPTableOnly}) {
		t.Errorf("router=%v warnings=%v", routerCalled, warnings)
	}
	// NetBIOS asked only the IPv4 hosts found, never this host
	if slices.Contains(netbiosHosts, netip.MustParseAddr("192.168.50.2")) || len(netbiosHosts) != 4 {
		t.Errorf("netbios hosts %v", netbiosHosts)
	}
	if lastDone != 2*253 || lastTotal != 2*253 {
		t.Errorf("progress %d/%d", lastDone, lastTotal)
	}
}

func TestRouterOutsideTheScopeIsNeverContacted(t *testing.T) {
	cfg := RouterConfig{Address: "10.0.0.1", TR064: &TR064Config{Password: "x"}}
	warns := queryRouter(context.Background(), cfg, func(netip.Addr) bool { return false }, func(Observation) {
		t.Fatal("no observation expected")
	})
	if !slices.Equal(warns, []string{WarnRouterOutOfScope}) {
		t.Fatalf("warnings = %v", warns)
	}
}

func TestRouterConfigRefusesDefaultCommunities(t *testing.T) {
	for _, c := range []RouterConfig{
		{Address: "192.168.1.1", SNMP: &SNMPConfig{Version: "2c", Community: "public"}},
		{Address: "192.168.1.1", SNMP: &SNMPConfig{Version: "2c", Community: "Private"}},
		{Address: "192.168.1.1", SNMP: &SNMPConfig{Version: "3", Username: "u", PrivProtocol: "AES", PrivPassword: "p"}},
		{Address: "192.168.1.1", TR064: &TR064Config{Username: "u"}},
		{Address: "127.0.0.1", TR064: &TR064Config{Password: "p"}},
		{Address: "192.168.1.1"},
	} {
		if c.Validate() == nil {
			t.Errorf("config accepted: %+v", c)
		}
	}
	ok := RouterConfig{Address: "192.168.1.1", SNMP: &SNMPConfig{Version: "3", Username: "u", AuthProtocol: "SHA256",
		AuthPassword: "a", PrivProtocol: "AES", PrivPassword: "p"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalNeighboursAreOnlyRecorded(t *testing.T) {
	n := Network{Target: netip.MustParsePrefix("fd00::/64")}
	mac, _ := net.ParseMAC("aa:bb:cc:00:00:30")
	var got []Observation
	emit := func(o Observation) { got = append(got, o) }
	emitNeighbour(n, neighbour{ip: netip.MustParseAddr("2001:db8::30"), mac: mac}, emit)
	emitNeighbour(n, neighbour{ip: netip.MustParseAddr("2001:db8::31")}, emit)            // no MAC
	emitNeighbour(n, neighbour{ip: netip.MustParseAddr("fd00:1::30"), mac: mac}, emit)    // ULA outside the target
	emitNeighbour(n, neighbour{ip: netip.MustParseAddr("fe80::30%eth0"), mac: mac}, emit) // link-local
	if len(got) != 1 || got[0].Method != methodGlobalNeighbour || got[0].IP.String() != "2001:db8::30" {
		t.Fatalf("unexpected %+v", got)
	}
}
