// Package discovery finds the hosts of the authorized networks (docs/07-DISCOVERY-FINGERPRINTING.md §1).
//
// Pipeline: interfaces → scope guard → [ARP ∥ ICMP ∥ mDNS ∥ SSDP/UPnP ∥ IPv6 NDP ∥ router] →
// NetBIOS + reverse DNS on the hosts found → observations merged per (address, method).
//
// Scope is enforced here, before anything is sent and again on every answer:
//   - active probes (ARP, ICMP, NetBIOS) go only to addresses of an authorized target that is
//     also a directly connected subnet; a target not connected to this host is skipped with a
//     warning (the agent never routes probes to other networks);
//   - multicast queries (mDNS, SSDP, IPv6 all-nodes echo) are sent only on the interfaces of
//     the connected authorized networks; they never leave the local link;
//   - every answer, including those of the router integrations, is kept only when its
//     address belongs to an authorized target (the backend checks it again).
//
// Nothing here logs in to a device: no port scan, no credential is tried. The router
// integrations (TR-064, SNMP) use only the credentials the owner configured on this agent,
// once; an authentication failure stops them (no retry, no guessing). What devices declare
// about themselves (mDNS, SSDP, UPnP) is reported as self-declared, never as verified.
package discovery

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Observation methods.
const (
	MethodARP     = "ARP"
	MethodSelf    = "SELF" // the agent host itself
	MethodICMP    = "ICMP"
	MethodMDNS    = "MDNS"
	MethodSSDP    = "SSDP"
	MethodUPnPIGD = "UPNP_IGD"
	MethodNetBIOS = "NETBIOS"
	MethodRDNS    = "RDNS"
	MethodNDP     = "NDP"
	MethodTR064   = "TR064"
	MethodSNMP    = "SNMP"

	// methodGlobalNeighbour marks a global IPv6 neighbour outside the targets: kept apart by the
	// collector and only attached to the in-scope observations with the same MAC.
	methodGlobalNeighbour = "global-neighbour"
	// DetailGlobalIPv6 lists those addresses in the details of an in-scope observation.
	DetailGlobalIPv6 = "globalIpv6"
	maxGlobalPerMAC  = 8
	maxGlobalTotal   = 256
)

// Warning codes (translated by the dashboard).
const (
	WarnTargetNotConnected  = "TARGET_NOT_CONNECTED"
	WarnHostLimitReached    = "HOST_LIMIT_REACHED"
	WarnARPTableOnly        = "ARP_TABLE_ONLY"
	WarnARPUnavailable      = "ARP_UNAVAILABLE"
	WarnInterfaceWithoutARP = "INTERFACE_WITHOUT_ARP"
	WarnARPError            = "ARP_ERROR"
	WarnICMPUnavailable     = "ICMP_UNAVAILABLE"
	WarnMDNSUnavailable     = "MDNS_UNAVAILABLE"
	WarnSSDPUnavailable     = "SSDP_UNAVAILABLE"
	WarnNetBIOSUnavailable  = "NETBIOS_UNAVAILABLE"
	WarnNDPTableOnly        = "NDP_TABLE_ONLY"
	WarnNDPUnavailable      = "NDP_UNAVAILABLE"
	WarnRouterOutOfScope    = "ROUTER_OUT_OF_SCOPE"
	WarnRouterAuthFailed    = "ROUTER_AUTH_FAILED"
	WarnRouterUnreachable   = "ROUTER_UNREACHABLE"
)

// maxDetailsBytes bounds the details of one observation (the backend refuses larger ones).
const maxDetailsBytes = 3000

// Interface is a local interface with its addresses (address + prefix length).
type Interface struct {
	Name      string
	Index     int
	MAC       net.HardwareAddr
	Addresses []netip.Prefix
}

// Network is an authorized target reachable on a local interface. IPv4 networks list the
// hosts to probe; IPv6 networks have none (a /64 cannot be swept): their hosts are found
// with the all-nodes echo, the neighbour table and mDNS.
type Network struct {
	Target    netip.Prefix
	Interface Interface
	Local     netip.Addr // address of this host on the interface
	Hosts     []netip.Addr
}

// IPv6 reports whether the network is an IPv6 one.
func (n Network) IPv6() bool { return n.Target.Addr().Is6() }

// Plan is what the discovery will probe.
type Plan struct {
	Networks   []Network
	Scope      []netip.Prefix // every authorized target, connected or not
	Warnings   []string
	TotalHosts int
}

// InScope reports whether ip belongs to an authorized target.
func (p Plan) InScope(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	for _, t := range p.Scope {
		if t.Contains(ip) {
			return true
		}
	}
	return false
}

// Observation is what one method learnt about one address.
type Observation struct {
	IP         netip.Addr
	MAC        string
	Method     string
	Interface  string
	Hostname   string
	Details    map[string]any
	ObservedAt time.Time
	Icon       *Icon // M23: icon declared by the device (UPnP), uploaded in its own batches
}

// Options bound the probing; Progress is called after each probed host.
type Options struct {
	RatePerSecond int
	Concurrency   int
	Progress      func(done, total, found int)
	Now           func() time.Time
	// Router enables the router integrations configured by the owner (nil: none).
	Router *RouterConfig

	tech *techniques // replaced in tests
}

// techniques are the discovery methods; each one reports through its callbacks and returns
// warning codes. Replaced in tests by fakes.
type techniques struct {
	arp     func(ctx context.Context, n Network, o Options, found func(netip.Addr, net.HardwareAddr), probed func()) []string
	icmp    func(ctx context.Context, n Network, o Options, found func(ip netip.Addr, ttl int), probed func()) []string
	mdns    func(ctx context.Context, n Network, emit func(Observation)) []string
	ssdp    func(ctx context.Context, n Network, emit func(Observation)) []string
	ssdpUni func(ctx context.Context, n Network, hosts []netip.Addr, emit func(Observation)) []string
	mdnsUni func(ctx context.Context, n Network, hosts []netip.Addr, emit func(Observation)) []string
	ndp     func(ctx context.Context, n Network, emit func(Observation)) []string
	netbios func(ctx context.Context, n Network, hosts []netip.Addr, emit func(Observation)) []string
	rdns    func(ctx context.Context, hosts []netip.Addr, emit func(Observation))
	router  func(ctx context.Context, cfg RouterConfig, inScope func(netip.Addr) bool, emit func(Observation)) []string
}

var defaultTechniques = techniques{arp: resolveARP, icmp: pingSweep, mdns: queryMDNS, ssdp: searchSSDP, ssdpUni: searchSSDPUnicast,
	mdnsUni: queryMDNSUnicast, ndp: discoverNDP, netbios: queryNetBIOS, rdns: reverseDNS, router: queryRouter}

// LocalInterfaces lists the interfaces that are up, with their unicast addresses.
func LocalInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := Interface{Name: iface.Name, Index: iface.Index, MAC: iface.HardwareAddr}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			bits, _ := ipnet.Mask.Size()
			entry.Addresses = append(entry.Addresses, netip.PrefixFrom(addr.Unmap(), bits))
		}
		if len(entry.Addresses) > 0 {
			out = append(out, entry)
		}
	}
	return out, nil
}

// MakePlan keeps, for each authorized target, the part reachable on a directly connected
// subnet: for IPv4 its hosts, up to maxHosts in total (the local address is not probed).
func MakePlan(targets []netip.Prefix, ifaces []Interface, maxHosts int) Plan {
	p := Plan{Scope: append([]netip.Prefix{}, targets...)}
	warn := map[string]bool{}
	for _, target := range targets {
		iface, local, ok := connected(target, ifaces)
		if !ok {
			warn[WarnTargetNotConnected] = true
			continue
		}
		n := Network{Target: target, Interface: iface, Local: local}
		if target.Addr().Is4() {
			for _, host := range hosts(target) {
				if host == local {
					continue
				}
				if p.TotalHosts == maxHosts {
					warn[WarnHostLimitReached] = true
					break
				}
				n.Hosts = append(n.Hosts, host)
				p.TotalHosts++
			}
		}
		p.Networks = append(p.Networks, n)
	}
	for w := range warn {
		p.Warnings = append(p.Warnings, w)
	}
	sort.Strings(p.Warnings)
	return p
}

// connected returns the interface whose subnet contains the whole target, with the local
// address on it (for IPv6 an address inside the target is preferred).
func connected(target netip.Prefix, ifaces []Interface) (Interface, netip.Addr, bool) {
	for _, iface := range ifaces {
		for _, a := range iface.Addresses {
			if a.Addr().Is4() == target.Addr().Is4() && a.Bits() <= target.Bits() &&
				a.Masked().Contains(target.Addr()) {
				return iface, a.Addr(), true
			}
		}
	}
	return Interface{}, netip.Addr{}, false
}

// hosts lists the usable addresses of an IPv4 prefix (without network and broadcast
// addresses when the prefix has them).
func hosts(p netip.Prefix) []netip.Addr {
	var out []netip.Addr
	first := p.Masked().Addr()
	for a := first; p.Contains(a); a = a.Next() {
		out = append(out, a)
		if !a.Next().IsValid() {
			break
		}
	}
	if p.Bits() <= 30 && len(out) >= 2 {
		out = out[1 : len(out)-1]
	}
	return out
}

// Run executes the plan and returns the observations (sorted by address and method) and the
// warnings.
func Run(ctx context.Context, plan Plan, o Options) ([]Observation, []string) {
	if o.Now == nil {
		o.Now = time.Now
	}
	t := defaultTechniques
	if o.tech != nil {
		t = *o.tech
	}
	c := &collector{plan: plan, now: o.Now, obs: map[obsKey]*Observation{}, global: map[netip.Addr]string{}}
	w := &warnings{set: map[string]bool{}}
	w.add(plan.Warnings...)
	for _, n := range plan.Networks {
		if n.Target.Contains(n.Local) {
			mac := ""
			if len(n.Interface.MAC) == 6 {
				mac = n.Interface.MAC.String()
			}
			c.add(Observation{IP: n.Local, MAC: mac, Method: MethodSelf, Interface: n.Interface.Name, Hostname: selfName()})
		}
	}

	// ARP and ICMP sweeps share the rate of the job: each gets half of it
	sweep := o
	sweep.RatePerSecond = max(1, o.RatePerSecond/2)
	total := max(1, 2*plan.TotalHosts)
	var done atomic.Int64
	probed := func() {
		d := done.Add(1)
		if o.Progress != nil {
			o.Progress(int(d), total, c.count())
		}
	}
	var v4, v6 []Network
	for _, n := range plan.Networks {
		if n.IPv6() {
			v6 = append(v6, n)
		} else {
			v4 = append(v4, n)
		}
	}
	var wg sync.WaitGroup
	parallel := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}
	parallel(func() {
		for _, n := range v4 {
			wanted := wantedHosts(n)
			w.add(t.arp(ctx, n, sweep, func(ip netip.Addr, mac net.HardwareAddr) {
				if wanted[ip] && len(mac) == 6 && !isZero(mac) {
					c.add(Observation{IP: ip, MAC: mac.String(), Method: MethodARP, Interface: n.Interface.Name})
				}
			}, probed)...)
		}
	})
	parallel(func() {
		for _, n := range v4 {
			wanted := wantedHosts(n)
			w.add(t.icmp(ctx, n, sweep, func(ip netip.Addr, ttl int) {
				if !wanted[ip] {
					return
				}
				o := Observation{IP: ip, Method: MethodICMP, Interface: n.Interface.Name}
				if ttl > 0 {
					o.Details = map[string]any{"ttl": ttl}
				}
				c.add(o)
			}, probed)...)
		}
	})
	for _, n := range v4 {
		parallel(func() { w.add(t.mdns(ctx, n, c.addOn(n))...) })
		parallel(func() { w.add(t.ssdp(ctx, n, c.addOn(n))...) })
	}
	for _, n := range v6 {
		parallel(func() { w.add(t.ndp(ctx, n, c.addOn(n))...) })
	}
	if o.Router != nil {
		parallel(func() { w.add(t.router(ctx, *o.Router, plan.InScope, c.add)...) })
	}
	wg.Wait()

	// M23: hosts found that did not answer the multicast UPnP search / mDNS query are asked
	// directly (name and services the device declares about itself)
	if ctx.Err() == nil {
		for _, n := range v4 {
			ssdpList, mdnsList := c.hostsWithout(n, MethodSSDP), c.hostsWithout(n, MethodMDNS)
			if len(ssdpList) > 0 {
				parallel(func() { w.add(t.ssdpUni(ctx, n, ssdpList, c.addOn(n))...) })
			}
			if len(mdnsList) > 0 {
				parallel(func() { w.add(t.mdnsUni(ctx, n, mdnsList, c.addOn(n))...) })
			}
		}
		wg.Wait()
	}

	// names of the hosts found: NetBIOS on each connected IPv4 network, then reverse DNS
	if ctx.Err() == nil {
		for _, n := range v4 {
			if list := c.hostsIn(n); len(list) > 0 {
				w.add(t.netbios(ctx, n, list, c.addOn(n))...)
			}
		}
	}
	if ctx.Err() == nil {
		t.rdns(ctx, c.hostsIn(Network{}), c.add)
	}
	return c.list(), w.list()
}

func wantedHosts(n Network) map[netip.Addr]bool {
	wanted := make(map[netip.Addr]bool, len(n.Hosts))
	for _, h := range n.Hosts {
		wanted[h] = true
	}
	return wanted
}

type obsKey struct {
	ip     netip.Addr
	method string
}

// collector merges the observations per (address, method) and drops everything outside the
// authorized targets.
type collector struct {
	mu   sync.Mutex
	plan Plan
	now  func() time.Time
	obs  map[obsKey]*Observation
	// global IPv6 neighbours outside the targets (address -> MAC): never listed as hosts
	global map[netip.Addr]string
}

func (c *collector) add(o Observation) {
	o.IP = o.IP.Unmap().WithZone("")
	if o.Method == methodGlobalNeighbour {
		c.mu.Lock()
		defer c.mu.Unlock()
		if isGlobal6(o.IP) && !c.plan.InScope(o.IP) && o.MAC != "" && len(c.global) < maxGlobalTotal {
			c.global[o.IP] = strings.ToLower(o.MAC)
		}
		return
	}
	if !o.IP.IsValid() || !c.plan.InScope(o.IP) {
		return
	}
	if o.ObservedAt.IsZero() {
		o.ObservedAt = c.now().UTC()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := obsKey{o.IP, o.Method}
	prev, ok := c.obs[key]
	if !ok {
		c.obs[key] = &o
		return
	}
	if prev.MAC == "" {
		prev.MAC = o.MAC
	}
	if prev.Hostname == "" {
		prev.Hostname = o.Hostname
	}
	if prev.Interface == "" {
		prev.Interface = o.Interface
	}
	if prev.Icon == nil {
		prev.Icon = o.Icon
	}
	for k, v := range o.Details {
		if prev.Details == nil {
			prev.Details = map[string]any{}
		}
		if _, exists := prev.Details[k]; !exists {
			prev.Details[k] = v
		}
	}
}

// addOn returns an emitter that sets the interface name of the network.
func (c *collector) addOn(n Network) func(Observation) {
	return func(o Observation) {
		if o.Interface == "" {
			o.Interface = n.Interface.Name
		}
		c.add(o)
	}
}

// hostsWithout lists the hosts found in n that have no observation of the given method.
func (c *collector) hostsWithout(n Network, method string) []netip.Addr {
	var out []netip.Addr
	for _, h := range c.hostsIn(n) {
		c.mu.Lock()
		_, done := c.obs[obsKey{ip: h, method: method}]
		c.mu.Unlock()
		if !done {
			out = append(out, h)
		}
	}
	return out
}

// count is the number of distinct addresses found.
func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[netip.Addr]bool{}
	for k := range c.obs {
		seen[k.ip] = true
	}
	return len(seen)
}

// hostsIn lists the addresses found in n (all of them for a zero Network), without this host.
func (c *collector) hostsIn(n Network) []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	self := map[netip.Addr]bool{}
	for k := range c.obs {
		if k.method == MethodSelf {
			self[k.ip] = true
		}
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for k := range c.obs {
		if self[k.ip] || seen[k.ip] || n.Target.IsValid() && !n.Target.Contains(k.ip) {
			continue
		}
		seen[k.ip] = true
		out = append(out, k.ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func (c *collector) list() []Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	byMAC := map[string][]string{}
	for ip, mac := range c.global {
		byMAC[mac] = append(byMAC[mac], ip.String())
	}
	out := make([]Observation, 0, len(c.obs))
	for _, o := range c.obs {
		if list := byMAC[strings.ToLower(o.MAC)]; o.MAC != "" && len(list) > 0 {
			sort.Strings(list)
			if len(list) > maxGlobalPerMAC {
				list = list[:maxGlobalPerMAC]
			}
			cp := *o
			cp.Details = map[string]any{DetailGlobalIPv6: list}
			for k, v := range o.Details {
				cp.Details[k] = v
			}
			o = &cp
		}
		if o.Details != nil {
			if data, err := json.Marshal(o.Details); err != nil || len(data) > maxDetailsBytes {
				o.Details = map[string]any{"truncated": true}
			}
		}
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP.Less(out[j].IP)
		}
		return out[i].Method < out[j].Method
	})
	return out
}

type warnings struct {
	mu  sync.Mutex
	set map[string]bool
}

func (w *warnings) add(codes ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range codes {
		w.set[c] = true
	}
}

func (w *warnings) list() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.set))
	for c := range w.set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// limiter paces the probes at ratePerSecond and stops when ctx is done.
type limiter struct {
	ticker *time.Ticker
}

func newLimiter(ratePerSecond int) *limiter {
	if ratePerSecond <= 0 {
		ratePerSecond = 1
	}
	return &limiter{ticker: time.NewTicker(time.Second / time.Duration(ratePerSecond))}
}

func (l *limiter) wait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-l.ticker.C:
		return true
	}
}

func (l *limiter) stop() { l.ticker.Stop() }

// sleep waits for d or until ctx is done.
func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func isZero(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

// probedAll reports every host of n as probed (method unavailable).
func probedAll(n Network, probed func()) {
	for range n.Hosts {
		probed()
	}
}

// peerAddr is the IP address of a UDP or IP peer.
func peerAddr(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		return ip.Unmap(), ok
	case *net.IPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		return ip.Unmap(), ok
	}
	return netip.Addr{}, false
}

// truncate limits a self-declared string to n runes.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
