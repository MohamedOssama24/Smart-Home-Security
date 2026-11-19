package portscan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// UDP is never swept (docs/08 §2): a port is contacted only with the request of its own
// protocol, the one every legitimate client sends, read-only:
//
//	53 DNS query (A localhost)        123 NTP client request (mode 3, never monlist/mode 7)
//	137 NetBIOS node status           161 SNMPv3 engine discovery (no community, no user)
//	1900 SSDP M-SEARCH (unicast)      3702 WS-Discovery Probe (+ ONVIF GetSystemDateAndTime)
//	5353 mDNS service list (unicast)  5683 CoAP GET /.well-known/core
//
// Answer => OPEN; ICMP port unreachable => CLOSED; silence => OPEN_FILTERED (never CLOSED).

const maxDatagram = 9000

// udpWait is how long a probe waits for an answer (shortened by the tests).
var udpWait = 2 * time.Second

type udpProbe struct {
	name    string
	request func(h *hostScan, port int) []byte
	// parse returns nil when the datagram is not an answer to the request
	parse func(request, response []byte) *Service
}

var udpProbes = map[int]*udpProbe{
	53:   {name: "dns", request: dnsRequest, parse: dnsParse},
	123:  {name: "ntp", request: ntpRequest, parse: ntpParse},
	137:  {name: "netbios-ns", request: nbstatRequest, parse: nbstatParse},
	161:  {name: "snmp", request: snmpRequest, parse: snmpParse},
	1900: {name: "ssdp", request: ssdpRequest, parse: ssdpParse},
	3702: {name: "ws-discovery", request: wsdRequest, parse: wsdParse},
	5353: {name: "mdns", request: mdnsRequest, parse: mdnsParse},
	5683: {name: "coap", request: coapRequest, parse: coapParse},
}

// probeUDP sends the protocol request of a well-known port (one retry when silent).
func (h *hostScan) probeUDP(ctx context.Context, port int) (Result, bool) {
	p := udpProbes[port]
	if p == nil {
		return Result{}, false // no safe probe: never contacted
	}
	actual := h.o.udpPort(port)
	result := Result{IP: h.ip, Protocol: UDP, Port: port, ObservedAt: h.o.Now().UTC()}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(h.ip, uint16(actual))))
	if err != nil {
		result.State, result.Reason = StateUnknown, "error"
		return result, true
	}
	defer conn.Close()
	request := p.request(h, actual)
	buf := make([]byte, maxDatagram)
	for attempt := 0; attempt < 2; attempt++ {
		if !h.wait(ctx) {
			return Result{}, false
		}
		if _, err := conn.Write(request); err != nil {
			if isRefused(err) {
				result.State, result.Reason = StateClosed, "icmp-port-unreachable"
				return result, true
			}
			result.State, result.Reason = StateUnknown, "error"
			return result, true
		}
		_ = conn.SetReadDeadline(time.Now().Add(udpWait))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if isRefused(err) {
					result.State, result.Reason = StateClosed, "icmp-port-unreachable"
					return result, true
				}
				if ctx.Err() != nil {
					return Result{}, false
				}
				break // silent: retry once
			}
			if svc := p.parse(request, buf[:n]); svc != nil {
				if port == 3702 {
					h.onvif(ctx, svc)
				}
				result.State, result.Reason, result.Service = StateOpen, "udp-response", svc
				return result, true
			}
			// unrelated datagram: keep waiting until the deadline
		}
	}
	result.State, result.Reason = StateOpenFiltered, "no-response"
	return result, true
}

func randomUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// --- DNS and mDNS ---------------------------------------------------------------------

func dnsQuery(name string, qtype dnsmessage.Type, id uint16, recursion bool) []byte {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: recursion},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}},
	}
	b, _ := msg.Pack()
	return b
}

func dnsAnswer(request, response []byte) (dnsmessage.Message, bool) {
	var msg dnsmessage.Message
	if len(request) < 2 || msg.Unpack(response) != nil || !msg.Header.Response ||
		msg.Header.ID != binary.BigEndian.Uint16(request) {
		return msg, false
	}
	return msg, true
}

func dnsRequest(*hostScan, int) []byte {
	return dnsQuery("localhost.", dnsmessage.TypeA, randomUint16(), true)
}

func dnsParse(request, response []byte) *Service {
	msg, ok := dnsAnswer(request, response)
	if !ok {
		return nil
	}
	s := confirmed("dns")
	s.Evidence["rcode"] = strings.TrimPrefix(msg.Header.RCode.String(), "RCode")
	s.Evidence["recursionAvailable"] = msg.Header.RecursionAvailable
	s.Evidence["answers"] = len(msg.Answers)
	return s
}

func mdnsRequest(*hostScan, int) []byte {
	return dnsQuery("_services._dns-sd._udp.local.", dnsmessage.TypePTR, randomUint16(), false)
}

func mdnsParse(request, response []byte) *Service {
	msg, ok := dnsAnswer(request, response)
	if !ok {
		return nil
	}
	s := confirmed("mdns")
	var services []string
	for _, a := range append(msg.Answers, msg.Additionals...) {
		if ptr, ok := a.Body.(*dnsmessage.PTRResource); ok && len(services) < 10 {
			services = append(services, clean(strings.TrimSuffix(ptr.PTR.String(), "."), 100))
		}
	}
	if len(services) > 0 {
		s.Evidence["services"] = services
	}
	return s
}

// --- NTP ------------------------------------------------------------------------------

func ntpRequest(*hostScan, int) []byte {
	b := make([]byte, 48)
	b[0] = 0x23 // version 4, mode 3 (client): never mode 6/7 (control, monlist)
	_, _ = rand.Read(b[40:48])
	return b
}

func ntpParse(request, response []byte) *Service {
	if len(response) < 48 || response[0]&0x07 != 4 || !bytes.Equal(response[24:32], request[40:48]) {
		return nil
	}
	s := confirmed("ntp")
	s.Evidence["version"] = int(response[0] >> 3 & 0x07)
	s.Evidence["stratum"] = int(response[1])
	return s
}

// --- NetBIOS node status --------------------------------------------------------------

func nbstatRequest(*hostScan, int) []byte {
	b := binary.BigEndian.AppendUint16(nil, randomUint16())
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	b = append(b, 0x20, 'C', 'K')
	for range 15 {
		b = append(b, 'A', 'A')
	}
	return append(b, 0, 0, 0x21, 0, 1) // NBSTAT, IN
}

func nbstatParse(request, response []byte) *Service {
	if len(response) < 12 || !bytes.Equal(response[:2], request[:2]) || response[2]&0x80 == 0 {
		return nil
	}
	off := 12
	if off < len(response) && response[off]&0xC0 == 0xC0 {
		off += 2
	} else {
		off += 34
	}
	off += 10 // type, class, TTL, length
	if off >= len(response) {
		return nil
	}
	count := int(response[off])
	off++
	s := confirmed("netbios-ns")
	var names []string
	for i := 0; i < count && off+18 <= len(response); i++ {
		entry := response[off : off+18]
		off += 18
		name := clean(strings.TrimRight(string(entry[:15]), " \x00"), 15)
		group := binary.BigEndian.Uint16(entry[16:])&0x8000 != 0
		if name != "" && entry[15] == 0x00 && !group {
			if _, ok := s.Evidence["computer"]; !ok {
				s.Evidence["computer"] = name
			}
		}
		if name != "" && len(names) < 5 {
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		s.Evidence["names"] = names
	}
	return s
}

// --- SNMPv3 engine discovery ----------------------------------------------------------

// snmpRequest is the RFC 3414 §4 discovery message: SNMPv3, noAuthNoPriv, empty engine id,
// empty user, empty GetRequest. It carries no community string and no credential: the
// agent answers with a Report holding its engine id, before any authentication.
func snmpRequest(*hostScan, int) []byte {
	id := make([]byte, 4)
	_, _ = rand.Read(id)
	id[0] &= 0x7F // positive INTEGER
	msg := []byte{0x30, 0x3e,
		0x02, 0x01, 0x03, // msgVersion 3
		0x30, 0x11, 0x02, 0x04, id[0], id[1], id[2], id[3], // msgID
		0x02, 0x03, 0x00, 0xff, 0xe3, // msgMaxSize 65507
		0x04, 0x01, 0x04, // msgFlags: reportable, noAuthNoPriv
		0x02, 0x01, 0x03, // msgSecurityModel USM
		0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
		0x30, 0x14, 0x04, 0x00, 0x04, 0x00, // contextEngineID, contextName
		0xa0, 0x0e, 0x02, 0x04, id[0], id[1], id[2], id[3], 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
	}
	return msg
}

// ber reads one BER TLV.
func ber(b []byte) (tag byte, value, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag, n, off := b[0], int(b[1]), 2
	if n&0x80 != 0 {
		size := n & 0x7F
		if size == 0 || size > 2 || len(b) < 2+size {
			return 0, nil, nil, false
		}
		n = 0
		for _, x := range b[2 : 2+size] {
			n = n<<8 | int(x)
		}
		off += size
	}
	if len(b) < off+n {
		return 0, nil, nil, false
	}
	return tag, b[off : off+n], b[off+n:], true
}

func berInt(v []byte) int {
	n := 0
	for _, x := range v {
		n = n<<8 | int(x)
	}
	return n
}

func snmpParse(_, response []byte) *Service {
	tag, msg, _, ok := ber(response)
	if !ok || tag != 0x30 {
		return nil
	}
	tag, version, rest, ok := ber(msg)
	if !ok || tag != 0x02 || berInt(version) != 3 {
		return nil
	}
	if _, _, rest, ok = ber(rest); !ok { // msgGlobalData
		return nil
	}
	tag, params, _, ok := ber(rest)
	if !ok || tag != 0x04 {
		return nil
	}
	s := confirmed("snmp")
	s.Version = "3"
	if tag, usm, _, ok := ber(params); ok && tag == 0x30 {
		if tag, engine, rest, ok := ber(usm); ok && tag == 0x04 && len(engine) > 0 {
			s.Evidence["engineId"] = hex.EncodeToString(engine[:min(len(engine), 32)])
			if len(engine) >= 4 && engine[0]&0x80 != 0 {
				s.Evidence["enterprise"] = int(binary.BigEndian.Uint32(engine) & 0x7FFFFFFF)
			}
			if tag, boots, _, ok := ber(rest); ok && tag == 0x02 {
				s.Evidence["engineBoots"] = berInt(boots)
			}
		}
	}
	return s
}

// --- SSDP -----------------------------------------------------------------------------

func ssdpRequest(h *hostScan, port int) []byte {
	return []byte(fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: %s\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n"+
		"USER-AGENT: %s\r\n\r\n", netip.AddrPortFrom(h.ip, uint16(port)), h.o.UserAgent))
}

func ssdpParse(_, response []byte) *Service {
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 200")) && !bytes.HasPrefix(response, []byte("HTTP/1.0 200")) {
		return nil
	}
	headers := parseHeaders(response)
	s := confirmed("ssdp")
	if server := clean(headers["server"], 128); server != "" {
		s.Evidence["server"] = server
		s.Product, s.Version = product(server)
	}
	if st := clean(headers["st"], 128); st != "" {
		s.Evidence["st"] = st
	}
	return s // LOCATION is not followed here (the discovery already read the description)
}

// --- CoAP -----------------------------------------------------------------------------

func coapRequest(*hostScan, int) []byte {
	b := []byte{0x40, 0x01} // version 1, confirmable, no token; GET
	b = binary.BigEndian.AppendUint16(b, randomUint16())
	b = append(b, 0xBB)                       // Uri-Path (11), length 11
	b = append(b, ".well-known"...)           //
	return append(append(b, 0x04), "core"...) // Uri-Path, length 4
}

func coapParse(request, response []byte) *Service {
	if len(response) < 4 || response[0]>>6 != 1 {
		return nil
	}
	ack := response[0]>>4&0x03 == 2
	if ack && !bytes.Equal(response[2:4], request[2:4]) {
		return nil
	}
	code := response[1]
	s := confirmed("coap")
	s.Evidence["code"] = fmt.Sprintf("%d.%02d", code>>5, code&0x1F)
	// skip the token and the options; the payload follows the 0xFF marker
	r := response
	off := 4 + int(r[0]&0x0F)
	extended := func(v int) (int, bool) {
		switch v {
		case 13:
			if off >= len(r) {
				return 0, false
			}
			off++
			return int(r[off-1]) + 13, true
		case 14:
			if off+2 > len(r) {
				return 0, false
			}
			off += 2
			return int(binary.BigEndian.Uint16(r[off-2:])) + 269, true
		case 15:
			return 0, false
		}
		return v, true
	}
	for off < len(r) && r[off] != 0xFF {
		b := r[off]
		off++
		_, okDelta := extended(int(b >> 4))
		length, okLength := extended(int(b & 0x0F))
		if !okDelta || !okLength {
			return s
		}
		off += length
	}
	if off < len(response) && response[off] == 0xFF {
		if payload := clean(string(response[off+1:]), maxEvidenceBytes); payload != "" {
			s.Evidence["resources"] = payload
		}
	}
	return s
}

// --- WS-Discovery and ONVIF -----------------------------------------------------------

func wsdRequest(*hostScan, int) []byte {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	id[6] = id[6]&0x0F | 0x40
	id[8] = id[8]&0x3F | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">` +
		`<e:Header><w:MessageID>urn:uuid:` + uuid + `</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>` +
		`<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>` +
		`<e:Body><d:Probe/></e:Body></e:Envelope>`)
}

// xmlTexts collects the text of the first element of each wanted local name. encoding/xml
// does not resolve external entities.
func xmlTexts(data []byte, names ...string) (map[string]string, bool) {
	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var current string
	matched := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return out, matched
		}
		switch t := tok.(type) {
		case xml.StartElement:
			current = t.Name.Local
			if current == "ProbeMatch" || current == "GetSystemDateAndTimeResponse" {
				matched = true
			}
		case xml.EndElement:
			current = ""
		case xml.CharData:
			for _, n := range names {
				if current == n {
					if _, seen := out[n]; !seen {
						out[n] = strings.TrimSpace(string(t))
					}
				}
			}
		}
	}
}

func wsdParse(_, response []byte) *Service {
	texts, matched := xmlTexts(response, "Types", "XAddrs", "Scopes")
	if !matched {
		return nil
	}
	s := confirmed("ws-discovery")
	if types := clean(texts["Types"], 200); types != "" {
		s.Evidence["types"] = types
		if strings.Contains(types, "NetworkVideoTransmitter") {
			s.Name = "onvif"
		}
	}
	var xaddrs []string
	for _, x := range strings.Fields(texts["XAddrs"]) {
		if len(xaddrs) < 3 {
			xaddrs = append(xaddrs, clean(x, 200))
		}
	}
	if len(xaddrs) > 0 {
		s.Evidence["xaddrs"] = xaddrs
	}
	if scopes := clean(texts["Scopes"], 300); scopes != "" {
		s.Evidence["scopes"] = scopes
	}
	return s
}

// onvif calls GetSystemDateAndTime, unauthenticated by the ONVIF specification, on the device
// service the device announced, only when that address is the scanned host itself (http).
func (h *hostScan) onvif(ctx context.Context, s *Service) {
	xaddrs, _ := s.Evidence["xaddrs"].([]string)
	for _, x := range xaddrs {
		u, err := url.Parse(x)
		if err != nil || u.Scheme != "http" || u.User != nil {
			continue
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || ip.Unmap() != h.ip.Unmap() {
			continue // never another host (SSRF)
		}
		body := `<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
			`<s:Body><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>`
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
		req.Header.Set("User-Agent", h.o.UserAgent)
		resp, err := h.httpClient(nil).Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
		_ = resp.Body.Close()
		if _, ok := xmlTexts(data); resp.StatusCode == http.StatusOK && ok {
			s.Name = "onvif"
			s.Evidence["onvifDeviceService"] = true
			return
		}
	}
}
