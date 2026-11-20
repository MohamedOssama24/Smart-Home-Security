package discovery

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// [MOCK] responder of a device that answers only direct questions: its own name for the
// reverse query, its service types, then the instance with port and TXT.
func mockUnicastMDNS(t *testing.T, questions *[]string) (netip.Addr, int) {
	dst := udpResponder(t, func(q []byte) [][]byte {
		var p dnsmessage.Parser
		if _, err := p.Start(q); err != nil {
			return nil
		}
		qs, _ := p.AllQuestions()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
		_ = b.StartAnswers()
		h := func(n string) dnsmessage.ResourceHeader {
			return dnsmessage.ResourceHeader{Name: name(n), Class: dnsmessage.ClassINET, TTL: 120}
		}
		for _, question := range qs {
			*questions = append(*questions, question.Name.String())
			switch question.Name.String() {
			case "1.0.0.127.in-addr.arpa.":
				_ = b.PTRResource(h("1.0.0.127.in-addr.arpa."), dnsmessage.PTRResource{PTR: name("MOCK-Phone.local.")})
			case "_services._dns-sd._udp.local.":
				_ = b.PTRResource(h("_services._dns-sd._udp.local."), dnsmessage.PTRResource{PTR: name("_companion-link._tcp.local.")})
			case "_companion-link._tcp.local.":
				_ = b.PTRResource(h("_companion-link._tcp.local."), dnsmessage.PTRResource{PTR: name("MOCK Phone._companion-link._tcp.local.")})
				_ = b.SRVResource(h("MOCK Phone._companion-link._tcp.local."), dnsmessage.SRVResource{Port: 49152, Target: name("MOCK-Phone.local.")})
				_ = b.TXTResource(h("MOCK Phone._companion-link._tcp.local."), dnsmessage.TXTResource{TXT: []string{"model=MockPhone1,1", "secret=no"}})
				// another address the device declares: not attributed (only what was asked)
				_ = b.AResource(h("other.local."), dnsmessage.AResource{A: [4]byte{127, 0, 0, 9}})
			}
		}
		out, err := b.Finish()
		if err != nil {
			return nil
		}
		return [][]byte{out}
	})
	return netip.MustParseAddr("127.0.0.1"), dst.Port
}

func TestUnicastMDNSGetsTheNameAndServicesTheDeviceDeclares(t *testing.T) {
	var questions []string
	host, port := mockUnicastMDNS(t, &questions)
	obs := mdnsUnicastExchange(context.Background(), clientConn(t), []netip.Addr{host}, port, 300*time.Millisecond)
	if len(obs) != 1 {
		t.Fatalf("observations %+v", obs)
	}
	o := obs[0]
	if o.IP != host || o.Method != MethodMDNS || o.Hostname != "MOCK-Phone" {
		t.Fatalf("observation %+v", o)
	}
	txt, _ := o.Details["txt"].(map[string]string)
	if txt["model"] != "MockPhone1,1" || txt["secret"] != "" {
		t.Fatalf("txt %+v", txt)
	}
	services, _ := o.Details["services"].([]mdnsService)
	if len(services) != 1 || services[0].Type != "_companion-link._tcp" || services[0].Port != 49152 {
		t.Fatalf("services %+v", services)
	}
	if len(questions) == 0 || questions[0] != "1.0.0.127.in-addr.arpa." {
		t.Fatalf("questions %v", questions)
	}
}

func TestUnicastMDNSAsksOnlyIPv4HostsInTheTarget(t *testing.T) {
	n := Network{Target: netip.MustParsePrefix("192.168.50.0/24"), Local: netip.MustParseAddr("127.0.0.1")}
	if w := queryMDNSUnicast(context.Background(), n, []netip.Addr{netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("fd00::1")}, func(o Observation) { t.Fatalf("unexpected %+v", o) }); w != nil {
		t.Fatalf("warnings %v", w)
	}
}

// [MOCK] a TV announcing a Cast service named by UUID and AirPlay by its readable name: the
// readable name wins whatever the order of the records.
func TestReadableHostNameIsPreferredToAGeneratedOne(t *testing.T) {
	src := netip.MustParseAddr("192.168.50.40")
	packet := func(names ...string) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
		_ = b.StartAnswers()
		for _, n := range names {
			_ = b.AResource(dnsmessage.ResourceHeader{Name: name(n), Class: dnsmessage.ClassINET, TTL: 120},
				dnsmessage.AResource{A: src.As4()})
		}
		out, _ := b.Finish()
		return out
	}
	for _, order := range [][]string{
		{"e6823421-5a9c-cd05-3526-2077531753ad.local.", "MOCKwebOSTV.local."},
		{"MOCKwebOSTV.local.", "e6823421-5a9c-cd05-3526-2077531753ad.local."},
	} {
		acc := &mdnsAnswers{types: map[string]bool{}, hosts: map[netip.Addr]*mdnsHost{}}
		acc.parse(src, packet(order[0]))
		acc.parse(src, packet(order[1]))
		if got := acc.hosts[src].hostname; got != "MOCKwebOSTV" {
			t.Fatalf("order %v: hostname %q", order, got)
		}
	}
}

func TestReverseName(t *testing.T) {
	if got := reverseName(netip.MustParseAddr("192.168.1.140")); got != "140.1.168.192.in-addr.arpa." {
		t.Fatal(got)
	}
}
