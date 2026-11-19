package discovery

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// mDNS / DNS-SD (RFC 6762/6763). Queries ask for unicast answers (QU bit) and are sent from
// an ephemeral port, so that they do not conflict with the responder of the operating system
// on port 5353. Answers that devices multicast anyway are not seen (declared limit).

const (
	mdnsRound       = 2 * time.Second
	maxMDNSServices = 24
	maxMDNSPerHost  = 16
	qu              = 1 << 15 // "unicast response" bit of the question class
)

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// TXT keys kept (model, name and manufacturer hints); everything else is ignored.
var mdnsTXTKeys = map[string]bool{"model": true, "md": true, "fn": true, "ty": true, "usb_mfg": true,
	"usb_mdl": true, "product": true, "am": true, "manufacturer": true, "mfg": true, "vendor": true, "osxvers": true}

// queryMDNS asks the link for the DNS-SD services, then for the instances of each service.
func queryMDNS(ctx context.Context, n Network, emit func(Observation)) []string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: n.Local.AsSlice()})
	if err != nil {
		return []string{WarnMDNSUnavailable}
	}
	defer conn.Close()
	p := ipv4.NewPacketConn(conn)
	iface := &net.Interface{Index: n.Interface.Index, Name: n.Interface.Name}
	_ = p.SetMulticastInterface(iface)
	_ = p.SetMulticastTTL(255)
	_ = p.SetMulticastLoopback(false)
	for _, o := range mdnsExchange(ctx, conn, mdnsGroup, mdnsRound) {
		emit(o)
	}
	return nil
}

type mdnsService struct {
	Type     string `json:"type"`
	Instance string `json:"instance,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type mdnsHost struct {
	hostname  string
	services  map[string]*mdnsService // by instance name
	txt       map[string]string
	addresses map[netip.Addr]bool // A/AAAA records of the hostname
}

// mdnsAnswers accumulates the answers per responder address.
type mdnsAnswers struct {
	mu    sync.Mutex
	types map[string]bool
	hosts map[netip.Addr]*mdnsHost
}

// mdnsExchange runs the two DNS-SD rounds against dst and returns the observations.
func mdnsExchange(ctx context.Context, conn net.PacketConn, dst net.Addr, round time.Duration) []Observation {
	acc := &mdnsAnswers{types: map[string]bool{}, hosts: map[netip.Addr]*mdnsHost{}}
	if q, err := mdnsQuery([]string{"_services._dns-sd._udp.local."}); err == nil {
		_, _ = conn.WriteTo(q, dst)
		readMDNS(ctx, conn, round, acc)
	}
	acc.mu.Lock()
	types := []string{"_device-info._tcp.local."}
	for t := range acc.types {
		if len(types) < maxMDNSServices {
			types = append(types, t)
		}
	}
	acc.mu.Unlock()
	sort.Strings(types[1:])
	if q, err := mdnsQuery(types); err == nil && ctx.Err() == nil {
		_, _ = conn.WriteTo(q, dst)
		readMDNS(ctx, conn, round, acc)
	}
	return acc.observations()
}

func mdnsQuery(names []string) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, name := range names {
		n, err := dnsmessage.NewName(name)
		if err != nil {
			continue
		}
		if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET | qu}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func readMDNS(ctx context.Context, conn net.PacketConn, d time.Duration, acc *mdnsAnswers) {
	deadline := time.Now().Add(d)
	buf := make([]byte, 9000)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(minTime(deadline, time.Now().Add(200*time.Millisecond)))
		size, from, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if src, ok := peerAddr(from); ok {
			acc.parse(src, buf[:size])
		}
	}
}

// parse records the answers of one response packet sent by src.
func (a *mdnsAnswers) parse(src netip.Addr, packet []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(packet)
	if err != nil || !h.Response {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	var records []dnsmessage.Resource
	for {
		r, err := p.Answer()
		if err != nil {
			break
		}
		records = append(records, r)
	}
	if err := p.SkipAllAuthorities(); err == nil {
		for {
			r, err := p.Additional()
			if err != nil {
				break
			}
			records = append(records, r)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	host := a.hosts[src]
	if host == nil {
		host = &mdnsHost{services: map[string]*mdnsService{}, txt: map[string]string{},
			addresses: map[netip.Addr]bool{}}
		a.hosts[src] = host
	}
	service := func(instance string) *mdnsService {
		s := host.services[instance]
		if s == nil && len(host.services) < maxMDNSPerHost {
			s = &mdnsService{Type: serviceType(instance), Instance: instanceName(instance)}
			host.services[instance] = s
		}
		return s
	}
	for _, r := range records {
		name := r.Header.Name.String()
		switch body := r.Body.(type) {
		case *dnsmessage.PTRResource:
			target := body.PTR.String()
			if strings.EqualFold(name, "_services._dns-sd._udp.local.") {
				if len(a.types) < 64 && strings.HasSuffix(target, ".local.") {
					a.types[strings.ToLower(target)] = true
				}
			} else if strings.HasPrefix(name, "_") {
				service(target)
			}
		case *dnsmessage.SRVResource:
			if s := service(name); s != nil {
				s.Port = int(body.Port)
			}
			if host.hostname == "" {
				host.hostname = trimLocal(body.Target.String())
			}
		case *dnsmessage.TXTResource:
			for _, kv := range body.TXT {
				k, v, ok := strings.Cut(kv, "=")
				if k = strings.ToLower(k); ok && mdnsTXTKeys[k] && len(host.txt) < 8 {
					host.txt[k] = truncate(v, 64)
				}
			}
		case *dnsmessage.AResource:
			ip := netip.AddrFrom4(body.A)
			if ip == src || host.hostname == "" {
				host.hostname = trimLocal(name)
			}
			host.addresses[ip] = true
		case *dnsmessage.AAAAResource:
			host.addresses[netip.AddrFrom16(body.AAAA)] = true
		}
	}
}

// observations: one per responder, plus one per other address it declared for itself
// (typically its IPv6 addresses); the collector keeps only those in scope.
func (a *mdnsAnswers) observations() []Observation {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Observation
	for src, h := range a.hosts {
		if h.hostname == "" && len(h.services) == 0 && len(h.txt) == 0 {
			continue
		}
		details := map[string]any{"selfDeclared": true}
		if len(h.services) > 0 {
			list := make([]mdnsService, 0, len(h.services))
			for _, s := range h.services {
				list = append(list, *s)
			}
			sort.Slice(list, func(i, j int) bool { return list[i].Type+list[i].Instance < list[j].Type+list[j].Instance })
			details["services"] = list
		}
		if len(h.txt) > 0 {
			details["txt"] = h.txt
		}
		hostname := truncate(h.hostname, 255)
		out = append(out, Observation{IP: src, Method: MethodMDNS, Hostname: hostname, Details: details})
		for ip := range h.addresses {
			if ip != src {
				out = append(out, Observation{IP: ip, Method: MethodMDNS, Hostname: hostname,
					Details: map[string]any{"selfDeclared": true, "declaredBy": src.String()}})
			}
		}
	}
	return out
}

// serviceType extracts "_ipp._tcp" from "Printer._ipp._tcp.local.".
func serviceType(instance string) string {
	parts := strings.Split(strings.TrimSuffix(instance, ".local."), ".")
	if len(parts) >= 2 {
		return truncate(parts[len(parts)-2]+"."+parts[len(parts)-1], 64)
	}
	return truncate(instance, 64)
}

func instanceName(instance string) string {
	t := serviceType(instance)
	name := strings.TrimSuffix(strings.TrimSuffix(instance, ".local."), "."+t)
	if name == t {
		return ""
	}
	return truncate(strings.ReplaceAll(name, `\ `, " "), 64)
}

func trimLocal(name string) string {
	return strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local")
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
