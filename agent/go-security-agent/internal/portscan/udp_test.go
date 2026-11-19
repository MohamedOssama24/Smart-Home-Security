package portscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// udpMock answers each datagram with reply(query) (nil: silent) and records the queries.
type udpMock struct {
	port    int
	mu      sync.Mutex
	queries [][]byte
}

func newUDPMock(t *testing.T, reply func(q []byte) []byte) *udpMock {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	m := &udpMock{port: conn.LocalAddr().(*net.UDPAddr).Port}
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := append([]byte{}, buf[:n]...)
			m.mu.Lock()
			m.queries = append(m.queries, q)
			m.mu.Unlock()
			if r := reply(q); r != nil {
				_, _ = conn.WriteToUDP(r, from)
			}
		}
	}()
	return m
}

func (m *udpMock) all() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queries
}

func dnsReply(q []byte, answers ...dnsmessage.Resource) []byte {
	var msg dnsmessage.Message
	if msg.Unpack(q) != nil {
		return nil
	}
	msg.Header.Response, msg.Header.RecursionAvailable = true, true
	msg.Answers = answers
	b, _ := msg.Pack()
	return b
}

func TestUDPProbesAndPolicy(t *testing.T) {
	old := udpWait
	udpWait = 300 * time.Millisecond
	t.Cleanup(func() { udpWait = old })

	onvifCalls := 0
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || !bytes.Contains(body, []byte("GetSystemDateAndTime")) ||
			bytes.Contains(body, []byte("Security")) {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		onvifCalls++
		_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` +
			`<tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>`))
	}))
	t.Cleanup(device.Close)

	mocks := map[int]*udpMock{
		53: newUDPMock(t, func(q []byte) []byte { return dnsReply(q) }),
		123: newUDPMock(t, func(q []byte) []byte {
			r := make([]byte, 48)
			r[0], r[1] = 0x24, 2 // version 4, mode 4 (server), stratum 2
			copy(r[24:32], q[40:48])
			return r
		}),
		137: newUDPMock(t, func(q []byte) []byte {
			r := append([]byte{}, q[:2]...)
			r = append(r, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
			r = append(r, q[12:46]...)
			r = append(r, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 37, 2)
			r = append(r, []byte("MOCK-PC        \x00\x04\x00")...)
			r = append(r, []byte("WORKGROUP      \x00\x84\x00")...)
			return append(r, make([]byte, 6)...)
		}),
		161: newUDPMock(t, func(q []byte) []byte {
			// [MOCK] Report with engine id 80001f8804... (enterprise 8072, net-snmp)
			engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x04, 'M', 'O', 'C', 'K'}
			usm := append([]byte{0x04, byte(len(engine))}, engine...)
			usm = append(usm, 0x02, 0x01, 0x07, 0x02, 0x01, 0x10, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00)
			params := append([]byte{0x30, byte(len(usm))}, usm...)
			body := []byte{0x02, 0x01, 0x03, 0x30, 0x03, 0x02, 0x01, 0x01}
			body = append(body, 0x04, byte(len(params)))
			body = append(body, params...)
			body = append(body, 0x30, 0x00)
			return append([]byte{0x30, byte(len(body))}, body...)
		}),
		1900: newUDPMock(t, func([]byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux/4.14 UPnP/1.0 MOCK-TV/3.0\r\nLOCATION: http://10.255.255.1/d.xml\r\n\r\n")
		}),
		3702: newUDPMock(t, func([]byte) []byte {
			return []byte(fmt.Sprintf(`<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">`+
				`<e:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>`+
				`<d:XAddrs>http://10.255.255.1/onvif/device_service %s/onvif/device_service</d:XAddrs>`+
				`<d:Scopes>onvif://www.onvif.org/name/MOCK-CAM</d:Scopes></d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>`, device.URL))
		}),
		5353: newUDPMock(t, func(q []byte) []byte {
			return dnsReply(q, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("_services._dns-sd._udp.local."),
					Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("_ipp._tcp.local.")}})
		}),
		5683: newUDPMock(t, func(q []byte) []byte {
			r := []byte{0x60, 0x45, q[2], q[3], 0xC1, 0x28, 0xFF} // ACK 2.05, Content-Format 40
			return append(r, `</sensors/temp>;rt="temperature"`...)
		}),
	}
	silent := newUDPMock(t, func([]byte) []byte { return nil })
	closed := func() int { // a UDP port with no listener: ICMP port unreachable
		c, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		p := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		return p
	}()
	// 53 is answered by a silent mock in a second scan, then by nothing at all
	run := func(mapping map[int]int, ports []int) ([]Result, []Summary) {
		results, sums, _ := Run(context.Background(), []netip.Addr{loopback}, Options{
			Profile: Profile{UDP: ports}, Lists: testLists(nil), Limits: fastLimits(), InScope: onlyLoopback,
			UserAgent: testAgent, udpPort: func(p int) int { return mapping[p] },
		})
		return results, sums
	}
	mapping := map[int]int{}
	var ports []int
	for p, m := range mocks {
		mapping[p] = m.port
		ports = append(ports, p)
	}
	sortInts(ports)
	results, sums := run(mapping, ports)
	if sums[0].UDP.Open != len(mocks) {
		t.Fatalf("summary %+v", sums[0].UDP)
	}
	byPort := map[int]*Service{}
	for _, r := range results {
		if r.Protocol != UDP || r.State != StateOpen {
			t.Fatalf("result %+v", r)
		}
		byPort[r.Port] = r.Service
	}
	check := func(port int, name string, key string, want any) {
		t.Helper()
		s := byPort[port]
		if s == nil || s.Name != name || s.Status != StatusConfirmed || fmt.Sprint(s.Evidence[key]) != fmt.Sprint(want) {
			t.Errorf("udp/%d: %+v", port, s)
		}
	}
	check(53, "dns", "recursionAvailable", true)
	check(123, "ntp", "stratum", 2)
	check(137, "netbios-ns", "computer", "MOCK-PC")
	check(161, "snmp", "enterprise", 8072)
	check(1900, "ssdp", "st", "upnp:rootdevice")
	check(3702, "onvif", "onvifDeviceService", true)
	check(5353, "mdns", "services", []string{"_ipp._tcp.local"})
	check(5683, "coap", "resources", `</sensors/temp>;rt="temperature"`)
	if onvifCalls != 1 {
		t.Errorf("ONVIF device service called %d times (the off-host XAddr must be ignored)", onvifCalls)
	}

	// silence => OPEN_FILTERED after one retry; nothing listening => CLOSED
	_, sums = run(map[int]int{53: silent.port, 123: closed}, []int{53, 123})
	if u := sums[0].UDP; u.OpenFiltered != 1 || u.Closed != 1 || u.Open != 0 {
		t.Fatalf("silent/closed %+v", u)
	}
	if n := len(silent.all()); n != 2 {
		t.Fatalf("silent port probed %d times, want 2", n)
	}

	// --- policy: only the protocol requests, never a credential or a control command --------
	snmp := mocks[161].all()[0]
	if bytes.Contains(snmp, []byte("public")) || bytes.Contains(snmp, []byte("private")) || snmp[4] != 0x03 {
		t.Errorf("SNMP request %x is not an SNMPv3 discovery", snmp)
	}
	if ntp := mocks[123].all()[0]; ntp[0]&0x07 != 3 || len(ntp) != 48 {
		t.Errorf("NTP request mode %d (monlist and control modes are forbidden)", ntp[0]&0x07)
	}
	if q := mocks[1900].all()[0]; !bytes.HasPrefix(q, []byte("M-SEARCH * HTTP/1.1\r\n")) {
		t.Errorf("SSDP request %q", q)
	}
	if q := mocks[5683].all()[0]; q[1] != 0x01 { // GET only
		t.Errorf("CoAP method %d", q[1])
	}
	if q := string(mocks[3702].all()[0]); !strings.Contains(q, "<d:Probe/>") {
		t.Errorf("WS-Discovery request %q", q)
	}
	var dnsQ dnsmessage.Message
	if err := dnsQ.Unpack(mocks[53].all()[0]); err != nil || len(dnsQ.Questions) != 1 || dnsQ.Questions[0].Type != dnsmessage.TypeA {
		t.Errorf("DNS request %+v", dnsQ)
	}
	if q := mocks[137].all()[0]; binary.BigEndian.Uint16(q[len(q)-4:]) != 0x21 {
		t.Errorf("NetBIOS request type %x", q[len(q)-4:])
	}
}

func TestUDPPortWithoutProbeIsNeverContacted(t *testing.T) {
	m := newUDPMock(t, func(q []byte) []byte { return q })
	results, sums, _ := Run(context.Background(), []netip.Addr{loopback}, Options{
		Profile: Profile{UDP: []int{69}}, Lists: testLists(nil), Limits: fastLimits(), InScope: onlyLoopback,
		udpPort: func(int) int { return m.port },
	})
	time.Sleep(50 * time.Millisecond)
	if len(results) != 0 || sums[0].UDP.Probed != 0 || len(m.all()) != 0 {
		t.Fatal("a UDP port without a protocol probe was contacted")
	}
}
