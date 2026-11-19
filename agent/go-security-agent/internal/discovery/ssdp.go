package discovery

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

// SSDP (UPnP discovery) and UPnP IGD. One M-SEARCH ssdp:all is multicast on the link (sent
// twice, UDP may be lost); each answering device may then be asked for its description, and
// an Internet gateway (IGD) for its external address and its active port mappings, which
// show what is exposed to the Internet. All of this is read-only and self-declared.

const (
	ssdpWindow         = 3 * time.Second
	maxSSDPDevices     = 64
	maxPortMappings    = 32
	maxSSDPServiceList = 12
)

var ssdpGroup = &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}

const mSearch = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n" +
	"ST: ssdp:all\r\nUSER-AGENT: shsc-agent/1 UPnP/1.1 discovery\r\n\r\n"

func searchSSDP(ctx context.Context, n Network, emit func(Observation)) []string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: n.Local.AsSlice()})
	if err != nil {
		return []string{WarnSSDPUnavailable}
	}
	defer conn.Close()
	p := ipv4.NewPacketConn(conn)
	_ = p.SetMulticastInterface(&net.Interface{Index: n.Interface.Index, Name: n.Interface.Name})
	_ = p.SetMulticastTTL(2)
	_ = p.SetMulticastLoopback(false)
	for _, o := range ssdpExchange(ctx, conn, ssdpGroup, ssdpWindow, n.Target.Contains) {
		emit(o)
	}
	return nil
}

type ssdpAnswer struct {
	server    string
	types     map[string]bool
	locations []string
}

// ssdpExchange sends the search to dst, collects the answers, then fetches the descriptions
// of the devices in scope.
func ssdpExchange(ctx context.Context, conn net.PacketConn, dst net.Addr, window time.Duration,
	inScope func(netip.Addr) bool) []Observation {
	for range 2 {
		_, _ = conn.WriteTo([]byte(mSearch), dst)
	}
	answers := map[netip.Addr]*ssdpAnswer{}
	deadline := time.Now().Add(window)
	buf := make([]byte, 4096)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(minTime(deadline, time.Now().Add(200*time.Millisecond)))
		size, from, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		src, ok := peerAddr(from)
		if !ok || !inScope(src) {
			continue
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:size])), nil)
		if err != nil {
			continue
		}
		resp.Body.Close()
		a := answers[src]
		if a == nil {
			if len(answers) >= maxSSDPDevices {
				continue
			}
			a = &ssdpAnswer{types: map[string]bool{}}
			answers[src] = a
		}
		if s := resp.Header.Get("Server"); s != "" && a.server == "" {
			a.server = truncate(s, 128)
		}
		if st := resp.Header.Get("St"); st != "" && len(a.types) < maxSSDPServiceList {
			a.types[truncate(st, 128)] = true
		}
		if loc := resp.Header.Get("Location"); loc != "" && len(a.locations) < 4 && !contains(a.locations, loc) {
			a.locations = append(a.locations, truncate(loc, 512))
		}
	}

	var (
		mu  sync.Mutex
		out []Observation
		wg  sync.WaitGroup
		sem = make(chan struct{}, 4)
	)
	for src, a := range answers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			obs := describe(ctx, src, a)
			mu.Lock()
			out = append(out, obs...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// describe builds the SSDP observation of a device and, for an Internet gateway, the IGD one.
func describe(ctx context.Context, src netip.Addr, a *ssdpAnswer) []Observation {
	details := map[string]any{"selfDeclared": true}
	if a.server != "" {
		details["server"] = a.server
	}
	if len(a.types) > 0 {
		types := make([]string, 0, len(a.types))
		for t := range a.types {
			types = append(types, t)
		}
		sort.Strings(types)
		details["searchTargets"] = types
	}
	out := []Observation{{IP: src, Method: MethodSSDP, Details: details}}
	client := deviceClient(src)
	for _, loc := range a.locations {
		u, err := safeURL(nil, loc, src)
		if err != nil {
			details["descriptionRefused"] = true // announced URL points elsewhere: never followed
			continue
		}
		root, err := fetchDescription(ctx, client, u)
		if err != nil {
			continue
		}
		d := root.Device
		for k, v := range map[string]string{"friendlyName": d.FriendlyName, "manufacturer": d.Manufacturer,
			"modelName": d.ModelName, "modelNumber": d.ModelNumber, "deviceType": d.DeviceType} {
			if v = strings.TrimSpace(v); v != "" {
				details[k] = truncate(v, 128)
			}
		}
		base := u
		if root.URLBase != "" {
			if b, err := safeURL(nil, root.URLBase, src); err == nil {
				base = b
			}
		}
		if igd, ok := queryIGD(ctx, client, base, &root.Device, src); ok {
			out = append(out, igd)
		}
		break
	}
	return out
}

// queryIGD reads the external address and the port mappings of an Internet gateway.
func queryIGD(ctx context.Context, client *http.Client, base *url.URL, root *upnpDevice, src netip.Addr) (Observation, bool) {
	var service upnpService
	root.walk(0, func(d *upnpDevice) {
		for _, s := range d.Services {
			if service.ServiceType == "" && (strings.Contains(s.ServiceType, ":WANIPConnection:") ||
				strings.Contains(s.ServiceType, ":WANPPPConnection:")) {
				service = s
			}
		}
	})
	if service.ServiceType == "" {
		return Observation{}, false
	}
	control, err := safeURL(base, service.ControlURL, src)
	if err != nil {
		return Observation{IP: src, Method: MethodUPnPIGD, Details: map[string]any{"selfDeclared": true,
			"controlRefused": true}}, true
	}
	details := map[string]any{"selfDeclared": true, "serviceType": truncate(service.ServiceType, 128)}
	if r, err := soapCall(ctx, client.Do, control, service.ServiceType, "GetExternalIPAddress", nil); err == nil {
		if ip, err := netip.ParseAddr(r["NewExternalIPAddress"]); err == nil {
			details["externalIp"] = ip.String()
		}
	}
	var mappings []map[string]any
	for i := 0; i < maxPortMappings && ctx.Err() == nil; i++ {
		r, err := soapCall(ctx, client.Do, control, service.ServiceType, "GetGenericPortMappingEntry",
			map[string]string{"NewPortMappingIndex": strconv.Itoa(i)})
		if err != nil {
			break // SOAP fault 713 (no more entries) or not supported
		}
		m := map[string]any{"protocol": truncate(r["NewProtocol"], 8),
			"internalClient": truncate(r["NewInternalClient"], 64),
			"enabled":        r["NewEnabled"] == "1" || strings.EqualFold(r["NewEnabled"], "true")}
		if p, err := strconv.Atoi(r["NewExternalPort"]); err == nil {
			m["externalPort"] = p
		}
		if p, err := strconv.Atoi(r["NewInternalPort"]); err == nil {
			m["internalPort"] = p
		}
		if d := strings.TrimSpace(r["NewPortMappingDescription"]); d != "" {
			m["description"] = truncate(d, 48)
		}
		mappings = append(mappings, m)
	}
	details["portMappings"] = mappings
	if mappings == nil {
		details["portMappings"] = []map[string]any{}
	}
	return Observation{IP: src, Method: MethodUPnPIGD, Details: details}, true
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}
