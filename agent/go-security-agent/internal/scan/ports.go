package scan

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"shsc/agent/internal/buildinfo"
	"shsc/agent/internal/cloud"
	"shsc/agent/internal/discovery"
	"shsc/agent/internal/portscan"
)

// portScanner is the default PortScanner: it scans only hosts that are inside an authorized
// target reachable on a local interface (the networks the discovery itself probed), with the
// limits of the signed job and the embedded port list of the profile.
func portScanner(log *slog.Logger) PortScanner {
	return func(ctx context.Context, job Job, hosts []netip.Addr, progress func(done, total int)) ([]portscan.Result, []portscan.Summary, []string) {
		profile, ok := portscan.DefaultLists.Profile(job.Profile)
		if !ok || job.Limits.Ports == nil {
			return nil, nil, nil // refused by Verify already
		}
		ifaces, err := discovery.LocalInterfaces()
		if err != nil {
			return nil, nil, []string{discovery.WarnTargetNotConnected}
		}
		plan := discovery.MakePlan(job.Prefixes, ifaces, job.Limits.MaxHosts)
		connected := make([]netip.Prefix, 0, len(plan.Networks))
		for _, n := range plan.Networks {
			connected = append(connected, n.Target)
		}
		l := job.Limits.Ports
		log.Info("port scan started", "profile", job.Profile, "hosts", len(hosts), "tcpPorts", len(profile.TCP),
			"udpPorts", len(profile.UDP), "listVersion", portscan.DefaultLists.Version)
		return portscan.Run(ctx, hosts, portscan.Options{
			Profile: profile, Lists: portscan.DefaultLists,
			Limits: portscan.Limits{RatePerSecond: l.RatePerSecond, Concurrency: l.Concurrency,
				PerHostConcurrency: l.PerHostConcurrency, PerHostRatePerSecond: l.PerHostRatePerSecond,
				Timeout: time.Duration(l.TimeoutMillis) * time.Millisecond},
			InScope: func(ip netip.Addr) bool {
				ip = ip.Unmap().WithZone("")
				return plan.InScope(ip) && slices.ContainsFunc(connected, func(p netip.Prefix) bool { return p.Contains(ip) })
			},
			Progress:  progress,
			UserAgent: "SmartHomeSecurityCheck-Agent/" + buildinfo.Get().Version,
		})
	}
}

// scanTargets are the discovered hosts whose ports are scanned: never the agent host itself
// and never IPv6 link-local addresses (their hosts are already reached over IPv4 or not at all).
func scanTargets(obs []discovery.Observation) []netip.Addr {
	self := map[netip.Addr]bool{}
	for _, o := range obs {
		if o.Method == discovery.MethodSelf {
			self[o.IP.Unmap()] = true
		}
	}
	seen := map[netip.Addr]bool{}
	var hosts []netip.Addr
	for _, o := range obs {
		ip := o.IP.Unmap().WithZone("")
		if !ip.IsValid() || self[ip] || seen[ip] || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() {
			continue
		}
		seen[ip] = true
		hosts = append(hosts, ip)
	}
	slices.SortFunc(hosts, func(a, b netip.Addr) int { return a.Compare(b) })
	return hosts
}

// summaryObservations turn the per-host counters into PORTSCAN observations.
func summaryObservations(job Job, sums []portscan.Summary, now time.Time) []discovery.Observation {
	out := make([]discovery.Observation, 0, len(sums))
	for _, s := range sums {
		out = append(out, discovery.Observation{IP: s.IP, Method: MethodPortScan, ObservedAt: now.UTC(),
			Details: map[string]any{"profile": job.Profile, "listVersion": portscan.DefaultLists.Version,
				"tcp": counters(s.TCP), "udp": counters(s.UDP), "paused": s.Paused}})
	}
	return out
}

func counters(c portscan.Counters) map[string]int {
	return map[string]int{"probed": c.Probed, "open": c.Open, "closed": c.Closed, "filtered": c.Filtered,
		"openFiltered": c.OpenFiltered, "unknown": c.Unknown}
}

func portResult(r portscan.Result) cloud.PortResult {
	p := cloud.PortResult{IP: r.IP.String(), Protocol: r.Protocol, Port: r.Port, State: r.State, Reason: r.Reason,
		ObservedAt: r.ObservedAt}
	if s := r.Service; s != nil {
		p.Service = &cloud.PortService{Name: s.Name, Product: s.Product, Version: s.Version, Status: s.Status,
			Confidence: s.Confidence, Evidence: s.Evidence, TLS: s.TLS}
	}
	return p
}
