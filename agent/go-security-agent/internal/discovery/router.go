package discovery

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Router integrations: the host table of the home router, read with the credentials the
// owner configured on this agent (never default credentials, never guessed). TR-064 is used
// on FRITZ!Box-like routers, SNMP on routers where the owner enabled it. Read-only actions
// only; an authentication failure stops the integration at once (no retry).

// RouterConfig is stored on the agent only (identity.SaveRouter); the backend never sees it.
type RouterConfig struct {
	Address string       `json:"address"`
	TR064   *TR064Config `json:"tr064,omitempty"`
	SNMP    *SNMPConfig  `json:"snmp,omitempty"`
}

// TR064Config: user and password of the router (digest authentication over HTTP).
type TR064Config struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
	Port     int    `json:"port,omitempty"` // default 49000
}

// SNMPConfig: v2c (community) or v3 (USM user).
type SNMPConfig struct {
	Version      string `json:"version"` // "2c" or "3"
	Community    string `json:"community,omitempty"`
	Username     string `json:"username,omitempty"`
	AuthProtocol string `json:"authProtocol,omitempty"` // SHA, SHA256, SHA512, MD5
	AuthPassword string `json:"authPassword,omitempty"`
	PrivProtocol string `json:"privProtocol,omitempty"` // AES, AES256, DES or empty
	PrivPassword string `json:"privPassword,omitempty"`
	Port         int    `json:"port,omitempty"` // default 161
}

const (
	tr064DefaultPort  = 49000
	maxRouterHosts    = 256
	maxSNMPEntries    = 1024
	snmpTimeout       = 2 * time.Second
	oidSysDescr       = ".1.3.6.1.2.1.1.1.0"
	oidSysName        = ".1.3.6.1.2.1.1.5.0"
	oidIPNetToMedia   = ".1.3.6.1.2.1.4.22.1.2" // ipNetToMediaPhysAddress
	tr064HostsService = "urn:dslforum-org:service:Hosts:1"
)

var (
	errRouterAuth = errors.New("router authentication failed")
	errEnough     = errors.New("entry limit reached")
)

// Validate checks the configuration before it is stored.
func (c RouterConfig) Validate() error {
	ip, err := netip.ParseAddr(c.Address)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return errors.New("router address must be a unicast IP address")
	}
	if c.TR064 == nil && c.SNMP == nil {
		return errors.New("no integration configured")
	}
	if t := c.TR064; t != nil && (t.Password == "" || t.Port < 0 || t.Port > 65535) {
		return errors.New("TR-064 needs a password and a valid port")
	}
	if s := c.SNMP; s != nil {
		if s.Port < 0 || s.Port > 65535 {
			return errors.New("invalid SNMP port")
		}
		switch s.Version {
		case "2c":
			if s.Community == "" || strings.EqualFold(s.Community, "public") || strings.EqualFold(s.Community, "private") {
				return errors.New("SNMP v2c needs the community configured by the owner (default communities are refused)")
			}
		case "3":
			if s.Username == "" {
				return errors.New("SNMP v3 needs a user name")
			}
			if _, ok := authProtocols[strings.ToUpper(s.AuthProtocol)]; s.AuthProtocol != "" && (!ok || s.AuthPassword == "") {
				return errors.New("SNMP v3: unknown authentication protocol or missing password")
			}
			if _, ok := privProtocols[strings.ToUpper(s.PrivProtocol)]; s.PrivProtocol != "" && (!ok || s.PrivPassword == "" || s.AuthProtocol == "") {
				return errors.New("SNMP v3: privacy needs authentication, a known protocol and a password")
			}
		default:
			return errors.New(`SNMP version must be "2c" or "3"`)
		}
	}
	return nil
}

// Integrations lists the configured integrations ("TR064", "SNMP"), without any secret.
func (c *RouterConfig) Integrations() []string {
	if c == nil {
		return nil
	}
	var out []string
	if c.TR064 != nil {
		out = append(out, MethodTR064)
	}
	if c.SNMP != nil {
		out = append(out, MethodSNMP)
	}
	return out
}

// queryRouter runs the configured integrations, only when the router address is in scope.
func queryRouter(ctx context.Context, cfg RouterConfig, inScope func(netip.Addr) bool, emit func(Observation)) []string {
	addr, err := netip.ParseAddr(cfg.Address)
	if err != nil || !inScope(addr) {
		return []string{WarnRouterOutOfScope}
	}
	addr = addr.Unmap()
	var warns []string
	report := func(err error) {
		switch {
		case err == nil:
		case errors.Is(err, errRouterAuth):
			warns = append(warns, WarnRouterAuthFailed)
		default:
			warns = append(warns, WarnRouterUnreachable)
		}
	}
	if cfg.TR064 != nil {
		port := cfg.TR064.Port
		if port == 0 {
			port = tr064DefaultPort
		}
		report(tr064Hosts(ctx, addr, port, cfg.TR064.Username, cfg.TR064.Password, emit))
	}
	if cfg.SNMP != nil && ctx.Err() == nil {
		report(snmpHosts(ctx, addr, *cfg.SNMP, emit))
	}
	return warns
}

// ---- TR-064 ----

// tr064Hosts reads the router description and its host table (Hosts:1 service).
func tr064Hosts(ctx context.Context, router netip.Addr, port int, user, password string, emit func(Observation)) error {
	client := deviceClient(router)
	desc, err := url.Parse("http://" + net.JoinHostPort(router.String(), strconv.Itoa(port)) + "/tr64desc.xml")
	if err != nil {
		return err
	}
	root, err := fetchDescription(ctx, client, desc)
	if err != nil {
		return err
	}
	var service upnpService
	root.Device.walk(0, func(d *upnpDevice) {
		for _, s := range d.Services {
			if service.ServiceType == "" && s.ServiceType == tr064HostsService {
				service = s
			}
		}
	})
	routerDetails := map[string]any{"router": true, "selfDeclared": true}
	for k, v := range map[string]string{"friendlyName": root.Device.FriendlyName,
		"manufacturer": root.Device.Manufacturer, "modelName": root.Device.ModelName} {
		if v = strings.TrimSpace(v); v != "" {
			routerDetails[k] = truncate(v, 128)
		}
	}
	if service.ServiceType == "" {
		emit(Observation{IP: router, Method: MethodTR064, Details: routerDetails})
		return errors.New("TR-064 Hosts service not available")
	}
	control, err := safeURL(desc, service.ControlURL, router)
	if err != nil {
		return err
	}
	auth := &digestAuth{client: client, user: user, password: password}
	r, err := soapCall(ctx, auth.do, control, service.ServiceType, "GetHostNumberOfEntries", nil)
	if err != nil {
		return err
	}
	emit(Observation{IP: router, Method: MethodTR064, Details: routerDetails})
	count, _ := strconv.Atoi(r["NewHostNumberOfEntries"])
	for i := 0; i < min(count, maxRouterHosts) && ctx.Err() == nil; i++ {
		e, err := soapCall(ctx, auth.do, control, service.ServiceType, "GetGenericHostEntry",
			map[string]string{"NewIndex": strconv.Itoa(i)})
		if err != nil {
			return err
		}
		if o, ok := tr064Entry(e); ok {
			emit(o)
		}
	}
	return nil
}

// tr064Entry maps an active host entry of the router to an observation.
func tr064Entry(e map[string]string) (Observation, bool) {
	ip, err := netip.ParseAddr(e["NewIPAddress"])
	if err != nil || e["NewActive"] != "1" && !strings.EqualFold(e["NewActive"], "true") {
		return Observation{}, false
	}
	o := Observation{IP: ip, Method: MethodTR064, Hostname: truncate(strings.TrimSpace(e["NewHostName"]), 255),
		Details: map[string]any{"source": "router"}}
	if mac, err := net.ParseMAC(e["NewMACAddress"]); err == nil && len(mac) == 6 && !isZero(mac) {
		o.MAC = mac.String()
	}
	if t := strings.TrimSpace(e["NewInterfaceType"]); t != "" {
		o.Details["interfaceType"] = truncate(t, 32)
	}
	return o, true
}

// digestAuth sends requests with HTTP digest authentication (RFC 7616, MD5, qop=auth). The
// challenge is reused for the following requests; a refused answer stops everything.
type digestAuth struct {
	client         *http.Client
	user, password string

	mu        sync.Mutex
	challenge map[string]string
	nc        int
}

func (a *digestAuth) do(req *http.Request) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		r := req.Clone(req.Context())
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r.Body = body
		}
		if h, ok := a.authorization(r); ok {
			r.Header.Set("Authorization", h)
		}
		resp, err := a.client.Do(r)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPBytes))
		resp.Body.Close()
		challenge := parseDigestChallenge(resp.Header.Get("WWW-Authenticate"))
		a.mu.Lock()
		retry := challenge != nil && (a.challenge == nil || strings.EqualFold(challenge["stale"], "true"))
		if retry {
			a.challenge, a.nc = challenge, 0
		}
		a.mu.Unlock()
		if !retry {
			return nil, errRouterAuth
		}
	}
	return nil, errRouterAuth
}

func (a *digestAuth) authorization(r *http.Request) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.challenge
	if c == nil {
		return "", false
	}
	a.nc++
	nc := fmt.Sprintf("%08x", a.nc)
	cnonce := make([]byte, 8)
	_, _ = rand.Read(cnonce)
	cn := hex.EncodeToString(cnonce)
	uri := r.URL.RequestURI()
	ha1 := md5hex(a.user + ":" + c["realm"] + ":" + a.password)
	ha2 := md5hex(r.Method + ":" + uri)
	qop := ""
	for _, q := range strings.Split(c["qop"], ",") {
		if strings.TrimSpace(q) == "auth" {
			qop = "auth"
		}
	}
	var resp string
	if qop != "" {
		resp = md5hex(ha1 + ":" + c["nonce"] + ":" + nc + ":" + cn + ":" + qop + ":" + ha2)
	} else {
		resp = md5hex(ha1 + ":" + c["nonce"] + ":" + ha2)
	}
	h := fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q`, a.user, c["realm"], c["nonce"], uri, resp)
	if qop != "" {
		h += fmt.Sprintf(`, qop=%s, nc=%s, cnonce=%q`, qop, nc, cn)
	}
	if o := c["opaque"]; o != "" {
		h += fmt.Sprintf(`, opaque=%q`, o)
	}
	return h + ", algorithm=MD5", true
}

// parseDigestChallenge parses a "Digest k=v, k="v"" header; nil when it is not a digest one.
func parseDigestChallenge(h string) map[string]string {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Digest") {
		return nil
	}
	out := map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		k, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		after = strings.TrimSpace(after)
		var v string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				break
			}
			v, after = after[1:end+1], after[end+2:]
		} else {
			v, after, _ = strings.Cut(after, ",")
			after = "," + after
		}
		out[k] = strings.TrimSpace(v)
		_, rest, _ = strings.Cut(after, ",")
		rest = strings.TrimSpace(rest)
	}
	if out["nonce"] == "" || out["algorithm"] != "" && !strings.EqualFold(out["algorithm"], "MD5") {
		return nil
	}
	return out
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---- SNMP ----

var authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{"MD5": gosnmp.MD5, "SHA": gosnmp.SHA,
	"SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512}

var privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{"DES": gosnmp.DES, "AES": gosnmp.AES,
	"AES192": gosnmp.AES192, "AES256": gosnmp.AES256}

// snmpHosts reads sysName/sysDescr and the IPv4 ARP table (ipNetToMediaTable) of the router.
func snmpHosts(ctx context.Context, router netip.Addr, cfg SNMPConfig, emit func(Observation)) error {
	g := snmpClient(ctx, router, cfg)
	if err := g.Connect(); err != nil {
		return err
	}
	defer g.Conn.Close()
	r, err := g.Get([]string{oidSysName, oidSysDescr})
	if err != nil {
		return snmpError(err)
	}
	details := map[string]any{"router": true, "selfDeclared": true}
	hostname := ""
	for _, v := range r.Variables {
		s, ok := v.Value.([]byte)
		if !ok {
			continue
		}
		switch v.Name {
		case oidSysName:
			hostname = truncate(strings.TrimSpace(string(s)), 255)
		case oidSysDescr:
			details["sysDescr"] = truncate(strings.TrimSpace(string(s)), 255)
		}
	}
	emit(Observation{IP: router, Method: MethodSNMP, Hostname: hostname, Details: details})
	entries := 0
	err = g.BulkWalk(oidIPNetToMedia, func(pdu gosnmp.SnmpPDU) error {
		if ip, mac, ok := snmpARPEntry(pdu); ok {
			emit(Observation{IP: ip, MAC: mac, Method: MethodSNMP, Details: map[string]any{"source": "router"}})
		}
		if entries++; entries >= maxSNMPEntries {
			return errEnough
		}
		return nil
	})
	if err != nil && !errors.Is(err, errEnough) {
		return snmpError(err)
	}
	return nil
}

func snmpClient(ctx context.Context, router netip.Addr, cfg SNMPConfig) *gosnmp.GoSNMP {
	port := cfg.Port
	if port == 0 {
		port = 161
	}
	g := &gosnmp.GoSNMP{Target: router.String(), Port: uint16(port), Transport: "udp", Context: ctx,
		Timeout: snmpTimeout, Retries: 1, MaxRepetitions: 20, MaxOids: gosnmp.MaxOids}
	if cfg.Version == "2c" {
		g.Version, g.Community = gosnmp.Version2c, cfg.Community
		return g
	}
	usm := &gosnmp.UsmSecurityParameters{UserName: cfg.Username, AuthenticationProtocol: gosnmp.NoAuth,
		PrivacyProtocol: gosnmp.NoPriv}
	flags := gosnmp.NoAuthNoPriv
	if p, ok := authProtocols[strings.ToUpper(cfg.AuthProtocol)]; ok {
		usm.AuthenticationProtocol, usm.AuthenticationPassphrase, flags = p, cfg.AuthPassword, gosnmp.AuthNoPriv
		if q, ok := privProtocols[strings.ToUpper(cfg.PrivProtocol)]; ok {
			usm.PrivacyProtocol, usm.PrivacyPassphrase, flags = q, cfg.PrivPassword, gosnmp.AuthPriv
		}
	}
	g.Version, g.SecurityModel, g.MsgFlags, g.SecurityParameters = gosnmp.Version3, gosnmp.UserSecurityModel, flags, usm
	return g
}

// snmpError maps the USM refusals to an authentication failure.
func snmpError(err error) error {
	for _, e := range []error{gosnmp.ErrWrongDigest, gosnmp.ErrUnknownUsername, gosnmp.ErrUnknownSecurityLevel,
		gosnmp.ErrDecryption} {
		if errors.Is(err, e) {
			return fmt.Errorf("%w: %v", errRouterAuth, err)
		}
	}
	return err
}

// snmpARPEntry decodes an ipNetToMediaPhysAddress entry: OID suffix ifIndex.a.b.c.d, value MAC.
func snmpARPEntry(pdu gosnmp.SnmpPDU) (netip.Addr, string, bool) {
	suffix, ok := strings.CutPrefix(pdu.Name, oidIPNetToMedia+".")
	if !ok {
		return netip.Addr{}, "", false
	}
	parts := strings.Split(suffix, ".")
	if len(parts) != 5 {
		return netip.Addr{}, "", false
	}
	ip, err := netip.ParseAddr(strings.Join(parts[1:], "."))
	if err != nil || !ip.Is4() {
		return netip.Addr{}, "", false
	}
	mac, ok := pdu.Value.([]byte)
	if !ok || len(mac) != 6 || isZero(mac) {
		return ip, "", true
	}
	return ip, net.HardwareAddr(mac).String(), true
}
