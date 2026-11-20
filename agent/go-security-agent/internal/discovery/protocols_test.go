package discovery

// [MOCK] responders on the loopback interface: they simulate devices answering mDNS, SSDP,
// UPnP IGD, NetBIOS and TR-064. No packet leaves this host.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"golang.org/x/net/dns/dnsmessage"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// udpResponder answers every datagram with reply(query); it stops with the test.
func udpResponder(t *testing.T, reply func(query []byte) [][]byte) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 9000)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			for _, r := range reply(append([]byte{}, buf[:n]...)) {
				_, _ = conn.WriteToUDP(r, from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func clientConn(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func TestMDNSCollectsServicesHostnameAndTXT(t *testing.T) {
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
			switch question.Name.String() {
			case "_services._dns-sd._udp.local.":
				_ = b.PTRResource(h("_services._dns-sd._udp.local."), dnsmessage.PTRResource{PTR: name("_ipp._tcp.local.")})
			case "_ipp._tcp.local.":
				_ = b.PTRResource(h("_ipp._tcp.local."), dnsmessage.PTRResource{PTR: name(`Office\ Printer._ipp._tcp.local.`)})
				_ = b.SRVResource(h(`Office\ Printer._ipp._tcp.local.`), dnsmessage.SRVResource{Port: 631, Target: name("printer.local.")})
				_ = b.TXTResource(h(`Office\ Printer._ipp._tcp.local.`), dnsmessage.TXTResource{TXT: []string{"ty=MOCK Laser 100", "adminurl=http://x", "pw=secret"}})
				_ = b.AResource(h("printer.local."), dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
				_ = b.AAAAResource(h("printer.local."), dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("fd00::20").As16()})
			}
		}
		out, _ := b.Finish()
		return [][]byte{out}
	})
	obs := mdnsExchange(context.Background(), clientConn(t), dst, 300*time.Millisecond)
	if len(obs) != 2 {
		t.Fatalf("observations %+v", obs)
	}
	o := obs[0]
	if o.IP != loopback {
		o = obs[1]
	}
	services, _ := o.Details["services"].([]mdnsService)
	txt, _ := o.Details["txt"].(map[string]string)
	if o.Hostname != "printer" || len(services) != 1 || services[0] != (mdnsService{Type: "_ipp._tcp", Instance: "Office Printer", Port: 631}) ||
		txt["ty"] != "MOCK Laser 100" || len(txt) != 1 || o.Details["selfDeclared"] != true {
		t.Fatalf("unexpected observation %+v", o)
	}
}

// mockIGD serves a UPnP description and a WANIPConnection control point.
func mockIGD(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/desc.xml":
			fmt.Fprint(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>MOCK Router</friendlyName>
<manufacturer>MOCK</manufacturer><modelName>R-1</modelName><softwareVersion>7.57</softwareVersion><deviceList><device><deviceList><device>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>`)
		case "/ctl":
			action := r.Header.Get("SOAPAction")
			buf := make([]byte, 2048)
			n, _ := r.Body.Read(buf)
			switch {
			case strings.Contains(action, "GetExternalIPAddress"):
				fmt.Fprint(w, `<s:Envelope><s:Body><u:R><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></u:R></s:Body></s:Envelope>`)
			case strings.Contains(string(buf[:n]), "<NewPortMappingIndex>0<"):
				fmt.Fprint(w, `<s:Envelope><s:Body><u:R><NewExternalPort>8080</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.20</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>camera</NewPortMappingDescription></u:R></s:Body></s:Envelope>`)
			default:
				w.WriteHeader(http.StatusInternalServerError) // fault 713: no more entries
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSSDPDescribesTheDeviceAndReadsTheIGDPortMappings(t *testing.T) {
	igd := mockIGD(t)
	var searches atomic.Int32
	dst := udpResponder(t, func(q []byte) [][]byte {
		if !strings.HasPrefix(string(q), "M-SEARCH * HTTP/1.1") {
			return nil
		}
		searches.Add(1)
		return [][]byte{[]byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: upnp:rootdevice\r\n" +
			"SERVER: MOCK/1.0 UPnP/1.0\r\nLOCATION: " + igd.URL + "/desc.xml\r\n\r\n")}
	})
	obs := ssdpExchange(context.Background(), clientConn(t), dst, 400*time.Millisecond, netip.Addr.IsLoopback)
	if searches.Load() != 2 || len(obs) != 2 {
		t.Fatalf("searches=%d observations=%+v", searches.Load(), obs)
	}
	ssdp, igdObs := obs[0], obs[1]
	if ssdp.Method != MethodSSDP {
		ssdp, igdObs = igdObs, ssdp
	}
	if ssdp.Details["friendlyName"] != "MOCK Router" || ssdp.Details["server"] != "MOCK/1.0 UPnP/1.0" ||
		ssdp.Details["softwareVersion"] != "7.57" {
		t.Fatalf("ssdp details %v", ssdp.Details)
	}
	m, _ := igdObs.Details["portMappings"].([]map[string]any)
	if igdObs.Method != MethodUPnPIGD || igdObs.Details["externalIp"] != "198.51.100.7" || len(m) != 1 ||
		m[0]["externalPort"] != 8080 || m[0]["internalClient"] != "192.168.1.20" || m[0]["enabled"] != true {
		t.Fatalf("igd details %v", igdObs.Details)
	}
}

func TestSSDPIgnoresAnswersOutsideTheScope(t *testing.T) {
	dst := udpResponder(t, func([]byte) [][]byte {
		return [][]byte{[]byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: http://127.0.0.1:1/\r\n\r\n")}
	})
	if obs := ssdpExchange(context.Background(), clientConn(t), dst, 300*time.Millisecond,
		func(netip.Addr) bool { return false }); len(obs) != 0 {
		t.Fatalf("out-of-scope device described: %+v", obs)
	}
}

func TestAnnouncedURLsCannotPointElsewhere(t *testing.T) {
	device := netip.MustParseAddr("192.168.1.1")
	base, _ := url.Parse("http://192.168.1.1:5000/desc.xml")
	for _, ref := range []string{
		"http://192.168.1.2/desc.xml",         // another host
		"http://169.254.169.254/latest/",      // metadata endpoint
		"https://192.168.1.1/desc.xml",        // other scheme
		"file:///etc/passwd",                  // local file
		"http://user:pw@192.168.1.1/desc.xml", // user information
		"http://router.local/desc.xml",        // name resolution
		"//10.0.0.1/ctl",                      // scheme-relative
	} {
		if _, err := safeURL(base, ref, device); err == nil {
			t.Errorf("URL accepted: %s", ref)
		}
	}
	if u, err := safeURL(base, "/ctl/WANIP", device); err != nil || u.String() != "http://192.168.1.1:5000/ctl/WANIP" {
		t.Fatalf("relative control URL refused: %v %v", u, err)
	}
	// the client itself cannot dial another address, even if asked to
	_, err := deviceClient(device).Get("http://127.0.0.1:1/")
	if err == nil || !strings.Contains(err.Error(), errUnsafeURL.Error()) {
		t.Fatalf("client dialed another host: %v", err)
	}
}

func TestNetBIOSReadsTheNameWorkgroupAndMAC(t *testing.T) {
	dst := udpResponder(t, func(q []byte) [][]byte {
		if len(q) < 50 {
			return nil
		}
		r := make([]byte, 12)
		copy(r, q[:2])
		binary.BigEndian.PutUint16(r[2:], 0x8400)
		binary.BigEndian.PutUint16(r[6:], 1)
		r = append(r, q[12:46]...)                     // name
		r = append(r, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0) // type, class, TTL, length (unchecked)
		entry := func(n string, suffix byte, flags uint16) []byte {
			e := []byte(fmt.Sprintf("%-15s", n))
			return binary.BigEndian.AppendUint16(append(e, suffix), flags)
		}
		r = append(r, 3)
		r = append(r, entry("MOCK-NAS", 0x20, 0x0400)...)
		r = append(r, entry("MOCK-NAS", 0x00, 0x0400)...)
		r = append(r, entry("WORKGROUP", 0x00, 0x8400)...)
		return [][]byte{append(r, 0x00, 0x11, 0x32, 0xaa, 0xbb, 0xcc)}
	})
	var got []Observation
	netbiosExchange(context.Background(), clientConn(t), []netip.Addr{loopback}, dst.Port, func(o Observation) {
		got = append(got, o)
	})
	if len(got) != 1 || got[0].Hostname != "MOCK-NAS" || got[0].Details["workgroup"] != "WORKGROUP" ||
		got[0].MAC != "00:11:32:aa:bb:cc" || got[0].Method != MethodNetBIOS {
		t.Fatalf("observations %+v", got)
	}
	if _, _, _, ok := parseNodeStatus([]byte{0, 1, 0x84}, 1); ok {
		t.Fatal("truncated answer accepted")
	}
}

// mockTR064 is a router that requires digest authentication for its host table.
func mockTR064(t *testing.T, password string, requests *atomic.Int32) *httptest.Server {
	const nonce = "MOCKNONCE"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			fmt.Fprint(w, `<root><device><friendlyName>MOCK Box</friendlyName><modelName>MOCK 7590</modelName>
<serviceList><service><serviceType>urn:dslforum-org:service:Hosts:1</serviceType><controlURL>/upnp/control/hosts</controlURL>
</service></serviceList></device></root>`)
			return
		}
		requests.Add(1)
		c := parseDigestChallenge(r.Header.Get("Authorization"))
		ha1 := md5hex("owner:MOCK:" + password)
		want := md5hex(ha1 + ":" + nonce + ":" + c["nc"] + ":" + c["cnonce"] + ":auth:" + md5hex(r.Method+":"+c["uri"]))
		if c == nil || c["response"] != want {
			w.Header().Set("WWW-Authenticate", `Digest realm="MOCK", nonce="`+nonce+`", qop="auth", algorithm=MD5`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		body := string(buf[:n])
		switch {
		case strings.Contains(r.Header.Get("SOAPAction"), "GetHostNumberOfEntries"):
			fmt.Fprint(w, `<s:Envelope><s:Body><u:R><NewHostNumberOfEntries>2</NewHostNumberOfEntries></u:R></s:Body></s:Envelope>`)
		case strings.Contains(body, "<NewIndex>0<"):
			fmt.Fprint(w, `<s:Envelope><s:Body><u:R><NewIPAddress>192.168.178.20</NewIPAddress><NewMACAddress>AA:BB:CC:00:00:20</NewMACAddress>
<NewHostName>MOCK-TV</NewHostName><NewInterfaceType>802.11</NewInterfaceType><NewActive>1</NewActive></u:R></s:Body></s:Envelope>`)
		default:
			fmt.Fprint(w, `<s:Envelope><s:Body><u:R><NewIPAddress>192.168.178.21</NewIPAddress><NewActive>0</NewActive></u:R></s:Body></s:Envelope>`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTR064ReadsTheActiveHostsWithDigestAuthentication(t *testing.T) {
	var requests atomic.Int32
	srv := mockTR064(t, "owner-secret", &requests)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	var mu sync.Mutex
	var got []Observation
	err := tr064Hosts(context.Background(), loopback, port, "owner", "owner-secret", func(o Observation) {
		mu.Lock()
		got = append(got, o)
		mu.Unlock()
	})
	if err != nil || len(got) != 2 {
		t.Fatalf("err=%v observations=%+v", err, got)
	}
	if got[0].IP != loopback || got[0].Details["modelName"] != "MOCK 7590" ||
		got[1].IP.String() != "192.168.178.20" || got[1].Hostname != "MOCK-TV" || got[1].MAC != "aa:bb:cc:00:00:20" {
		t.Fatalf("observations %+v", got)
	}
	if requests.Load() != 4 { // one challenge, then 3 authenticated calls reusing it
		t.Fatalf("requests = %d", requests.Load())
	}
}

func TestTR064StopsAtTheFirstAuthenticationFailure(t *testing.T) {
	var requests atomic.Int32
	srv := mockTR064(t, "owner-secret", &requests)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	err := tr064Hosts(context.Background(), loopback, port, "owner", "wrong", func(o Observation) {
		if o.Method == MethodTR064 && o.IP != loopback {
			t.Fatal("host table read without valid credentials")
		}
	})
	if err == nil || !strings.Contains(err.Error(), errRouterAuth.Error()) || requests.Load() != 2 {
		t.Fatalf("err=%v requests=%d (expected one challenge and one refused attempt)", err, requests.Load())
	}
	warns := queryRouter(context.Background(), RouterConfig{Address: "127.0.0.1",
		TR064: &TR064Config{Username: "owner", Password: "wrong", Port: port}}, netip.Addr.IsLoopback, func(Observation) {})
	if len(warns) != 1 || warns[0] != WarnRouterAuthFailed {
		t.Fatalf("warnings = %v", warns)
	}
}

// mockSNMP is a [MOCK] SNMPv2c router: it answers Get (sysName, sysDescr) and GetBulk on the
// ARP table only for the owner's community; like real agents, a wrong community gets no reply.
func mockSNMP(t *testing.T, community string, requests *atomic.Int32) int {
	t.Helper()
	mib := []gosnmp.SnmpPDU{
		{Name: oidSysDescr, Type: gosnmp.OctetString, Value: []byte("MOCK router firmware 1.0")},
		{Name: oidSysName, Type: gosnmp.OctetString, Value: []byte("mock-router")},
		{Name: oidIPNetToMedia + ".2.192.168.1.1", Type: gosnmp.OctetString, Value: []byte{0x02, 0, 0, 0, 0, 0x01}},
		{Name: oidIPNetToMedia + ".2.192.168.1.20", Type: gosnmp.OctetString, Value: []byte{0x02, 0, 0, 0, 0, 0x20}},
		{Name: oidIPNetToMedia + ".2.192.168.1.30", Type: gosnmp.OctetString, Value: []byte{0, 0, 0, 0, 0, 0}},
		{Name: ".1.3.6.1.2.1.4.22.1.3.2.192.168.1.1", Type: gosnmp.IPAddress, Value: "192.168.1.1"}, // next column
	}
	dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c}
	addr := udpResponder(t, func(q []byte) [][]byte {
		requests.Add(1)
		req, err := dec.SnmpDecodePacket(q)
		if err != nil || req.Community != community {
			return nil
		}
		resp := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: community, PDUType: gosnmp.GetResponse,
			RequestID: req.RequestID}
		switch req.PDUType {
		case gosnmp.GetRequest:
			for _, v := range req.Variables {
				for _, m := range mib {
					if m.Name == v.Name {
						resp.Variables = append(resp.Variables, m)
					}
				}
			}
		case gosnmp.GetBulkRequest:
			start := 2 // first ARP entry, when the walk starts at the table root
			for i, m := range mib {
				if m.Name == req.Variables[0].Name {
					start = i + 1
				}
			}
			resp.Variables = mib[min(start, len(mib)-1):]
		}
		out, err := resp.MarshalMsg()
		if err != nil {
			t.Error(err)
			return nil
		}
		return [][]byte{out}
	})
	return addr.Port
}

func TestSNMPReadsTheRouterNameAndARPTable(t *testing.T) {
	var requests atomic.Int32
	port := mockSNMP(t, "owner-community", &requests)
	var got []Observation
	warns := queryRouter(context.Background(), RouterConfig{Address: "127.0.0.1",
		SNMP: &SNMPConfig{Version: "2c", Community: "owner-community", Port: port}}, netip.Addr.IsLoopback,
		func(o Observation) { got = append(got, o) })
	if len(warns) != 0 || len(got) != 4 {
		t.Fatalf("warnings=%v observations=%+v", warns, got)
	}
	if got[0].IP != loopback || got[0].Hostname != "mock-router" || got[0].Details["sysDescr"] != "MOCK router firmware 1.0" {
		t.Fatalf("router = %+v", got[0])
	}
	want := []string{"192.168.1.1 02:00:00:00:00:01", "192.168.1.20 02:00:00:00:00:20", "192.168.1.30 "}
	for i, w := range want {
		if o := got[i+1]; o.Method != MethodSNMP || o.IP.String()+" "+o.MAC != w {
			t.Fatalf("entry %d = %v %q, want %q", i, o.IP, o.MAC, w)
		}
	}
}

func TestSNMPWrongCommunityIsNotRetriedWithOtherValues(t *testing.T) {
	var requests atomic.Int32
	port := mockSNMP(t, "owner-community", &requests)
	var got int
	warns := queryRouter(context.Background(), RouterConfig{Address: "127.0.0.1",
		SNMP: &SNMPConfig{Version: "2c", Community: "wrong-community", Port: port}}, netip.Addr.IsLoopback,
		func(Observation) { got++ })
	// v2c has no explicit refusal: the agent sees a timeout. Only the configured community is
	// sent, once plus one transport retry; no other community is ever tried.
	if got != 0 || len(warns) != 1 || warns[0] != WarnRouterUnreachable || requests.Load() != 2 {
		t.Fatalf("observations=%d warnings=%v requests=%d", got, warns, requests.Load())
	}
}

func TestSNMPARPEntries(t *testing.T) {
	ip, mac, ok := snmpARPEntry(gosnmp.SnmpPDU{Name: oidIPNetToMedia + ".3.192.168.1.20",
		Value: []byte{0xaa, 0xbb, 0xcc, 0, 0, 0x20}})
	if !ok || ip.String() != "192.168.1.20" || mac != "aa:bb:cc:00:00:20" {
		t.Fatalf("%v %v %v", ip, mac, ok)
	}
	if _, _, ok := snmpARPEntry(gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.5.0", Value: []byte("x")}); ok {
		t.Fatal("unrelated OID accepted")
	}
	if snmpError(gosnmp.ErrWrongDigest) == nil || !strings.Contains(snmpError(gosnmp.ErrWrongDigest).Error(), errRouterAuth.Error()) {
		t.Fatal("wrong SNMPv3 digest must be an authentication failure")
	}
}
