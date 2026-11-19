// Package homeassistant reads, with the long-lived token created by the owner, the device
// inventory of the owner's Home Assistant through its official REST API (Milestone 15,
// docs/24-INTEGRATIONS.md). It is read-only: only GET /api/config and POST /api/template
// (rendering a template, which changes nothing) are called. The URL and the token stay on the
// agent; the backend receives only the inventory.
package homeassistant

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Warnings added to the scan (each one makes it COMPLETED_WITH_WARNINGS).
const (
	WarnOutOfScope      = "HA_OUT_OF_SCOPE"        // address outside the authorized networks: no packet sent
	WarnUnreachable     = "HA_UNREACHABLE"         // connection, timeout or TLS error
	WarnAuthFailed      = "HA_AUTH_FAILED"         // token refused (401/403): one attempt, no retry
	WarnInvalidResponse = "HA_INVALID_RESPONSE"    // unexpected status or body
	WarnPlainHTTP       = "HA_PLAIN_HTTP"          // the token travels unencrypted on the LAN
	WarnTruncated       = "HA_INVENTORY_TRUNCATED" // more than MaxDevices devices
)

// Protocols of the devices (closed list, as on the backend).
const (
	ProtocolZigbee    = "ZIGBEE"
	ProtocolZWave     = "ZWAVE"
	ProtocolMatter    = "MATTER"
	ProtocolThread    = "THREAD"
	ProtocolBluetooth = "BLUETOOTH"
	ProtocolIP        = "IP"
	ProtocolOther     = "OTHER"
)

const (
	// MaxDevices is the maximum number of devices uploaded (one backend batch).
	MaxDevices   = 500
	maxBody      = 4 << 20
	timeout      = 15 * time.Second
	minTokenLen  = 20
	maxTokenLen  = 1024
	maxMACs      = 8
	maxEntities  = 10000
	defaultPortH = 8123
)

// Config is set by the owner with "shsc-agent homeassistant set".
type Config struct {
	// URL is http(s)://IP[:port] of Home Assistant: an IP literal (no name resolution), no path.
	URL string `json:"url"`
	// Token is a long-lived access token created by the owner in their Home Assistant profile.
	Token string `json:"token"`
	// TLSServerName, optional: the name in the HTTPS certificate when it does not contain the IP.
	TLSServerName string `json:"tlsServerName,omitempty"`
}

var (
	tokenPattern      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
)

// Validate checks the settings; the error never contains the token.
func (c Config) Validate() error {
	if _, _, err := c.endpoint(); err != nil {
		return err
	}
	if len(c.Token) < minTokenLen || len(c.Token) > maxTokenLen || !tokenPattern.MatchString(c.Token) {
		return errors.New("the token must be the long-lived access token created in the Home Assistant profile")
	}
	if c.TLSServerName != "" && (len(c.TLSServerName) > 253 || !serverNamePattern.MatchString(c.TLSServerName)) {
		return errors.New("invalid TLS server name")
	}
	return nil
}

// Address is the IP of Home Assistant (zero when the URL is invalid).
func (c Config) Address() netip.Addr {
	addr, _, err := c.endpoint()
	if err != nil {
		return netip.Addr{}
	}
	return addr.Addr()
}

// HTTPS tells whether the token is protected by TLS.
func (c Config) HTTPS() bool {
	_, https, err := c.endpoint()
	return err == nil && https
}

func (c Config) endpoint() (netip.AddrPort, bool, error) {
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return netip.AddrPort{}, false, errors.New("the URL must be http(s)://IP[:port] without path")
	}
	addr, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]"))
	if err != nil || addr.Zone() != "" {
		return netip.AddrPort{}, false, errors.New("the URL must contain the IP address of Home Assistant, not a name")
	}
	port := defaultPortH
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return netip.AddrPort{}, false, errors.New("invalid port")
		}
		port = n
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), u.Scheme == "https", nil
}

// Device is a device of the Home Assistant device registry.
type Device struct {
	Name         string   `json:"name,omitempty"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Model        string   `json:"model,omitempty"`
	SWVersion    string   `json:"swVersion,omitempty"`
	Protocol     string   `json:"protocol"`
	MACs         []string `json:"macs"`
	Entities     int      `json:"entities"`
}

// Inventory is what is uploaded to the backend (never the URL path or the token).
type Inventory struct {
	IP         netip.Addr
	Version    string
	HTTPS      bool
	Devices    []Device
	Truncated  bool
	ObservedAt time.Time
}

// deviceTemplate lists the devices that have at least one entity, with the registry fields
// needed to classify them. Rendering a template is read-only.
const deviceTemplate = `{%- set ns = namespace(out=[]) -%}
{%- for d in states | map(attribute='entity_id') | map('device_id') | reject('none') | unique -%}
{%- set ns.out = ns.out + [{"n": device_attr(d, 'name_by_user') or device_attr(d, 'name'),
 "ma": device_attr(d, 'manufacturer'), "mo": device_attr(d, 'model'), "sw": device_attr(d, 'sw_version'),
 "ids": device_attr(d, 'identifiers') | map('list') | list,
 "conn": device_attr(d, 'connections') | map('list') | list,
 "e": device_entities(d) | length}] -%}
{%- endfor -%}
{{ ns.out | to_json }}`

type rawDevice struct {
	Name         *string `json:"n"`
	Manufacturer *string `json:"ma"`
	Model        *string `json:"mo"`
	SWVersion    *string `json:"sw"`
	Identifiers  [][]any `json:"ids"`
	Connections  [][]any `json:"conn"`
	Entities     int     `json:"e"`
}

// Collect reads the inventory when the address of Home Assistant is in scope; otherwise it
// sends nothing. A refused token stops immediately (no retry, no variant).
func Collect(ctx context.Context, cfg Config, inScope func(netip.Addr) bool, now func() time.Time) (*Inventory, []string) {
	target, https, err := cfg.endpoint()
	if err != nil || !inScope(target.Addr()) {
		return nil, []string{WarnOutOfScope}
	}
	var warns []string
	if !https {
		warns = append(warns, WarnPlainHTTP)
	}
	c := newClient(cfg, target, https)
	var conf struct {
		Version string `json:"version"`
	}
	if w := c.call(ctx, http.MethodGet, "/api/config", nil, &conf); w != "" {
		return nil, append(warns, w)
	}
	var raw []rawDevice
	body, _ := json.Marshal(map[string]string{"template": deviceTemplate})
	if w := c.call(ctx, http.MethodPost, "/api/template", body, &raw); w != "" {
		return nil, append(warns, w)
	}
	inv := &Inventory{IP: target.Addr(), HTTPS: https, ObservedAt: now().UTC(), Devices: []Device{}}
	if versionPattern.MatchString(conf.Version) {
		inv.Version = conf.Version
	}
	for _, r := range raw {
		if len(inv.Devices) == MaxDevices {
			inv.Truncated = true
			warns = append(warns, WarnTruncated)
			break
		}
		inv.Devices = append(inv.Devices, device(r))
	}
	return inv, warns
}

var versionPattern = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,40}$`)

type client struct {
	http  *http.Client
	base  string
	token string
}

// newClient can reach only the configured address: no proxy, no redirect, bounded time.
func newClient(cfg Config, target netip.AddrPort, https bool) *client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target.String())
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.TLSServerName},
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	scheme := "http"
	if https {
		scheme = "https"
	}
	return &client{
		http: &http.Client{Transport: transport, Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base:  scheme + "://" + target.String(),
		token: cfg.Token,
	}
}

// call returns "" on success, otherwise the warning to report.
func (c *client) call(ctx context.Context, method, path string, body []byte, out any) string {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return WarnInvalidResponse
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return WarnUnreachable
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return WarnAuthFailed
	case resp.StatusCode != http.StatusOK || err != nil || len(data) > maxBody:
		return WarnInvalidResponse
	}
	if json.Unmarshal(data, out) != nil {
		return WarnInvalidResponse
	}
	return ""
}

func device(r rawDevice) Device {
	d := Device{Name: text(r.Name, 255), Manufacturer: text(r.Manufacturer, 128), Model: text(r.Model, 128),
		SWVersion: text(r.SWVersion, 64), MACs: []string{}, Entities: min(max(r.Entities, 0), maxEntities)}
	for _, c := range r.Connections {
		if len(c) == 2 && c[0] == "mac" && len(d.MACs) < maxMACs {
			if mac, ok := c[1].(string); ok {
				if hw, err := net.ParseMAC(mac); err == nil && len(hw) == 6 {
					if s := hw.String(); !contains(d.MACs, s) {
						d.MACs = append(d.MACs, s)
					}
				}
			}
		}
	}
	d.Protocol = protocol(r)
	return d
}

// protocol classifies a device from the integrations that know it and its connections.
func protocol(r rawDevice) string {
	for _, id := range r.Identifiers {
		if len(id) == 0 {
			continue
		}
		domain, _ := id[0].(string)
		value := ""
		if len(id) > 1 {
			value, _ = id[1].(string)
		}
		switch {
		case domain == "zha" || domain == "deconz" || (domain == "mqtt" && strings.HasPrefix(value, "zigbee2mqtt")):
			return ProtocolZigbee
		case domain == "zwave_js" || domain == "zwave_me":
			return ProtocolZWave
		case domain == "matter":
			return ProtocolMatter
		case domain == "thread" || domain == "otbr":
			return ProtocolThread
		case domain == "bluetooth" || domain == "bthome" || domain == "ibeacon" || strings.HasSuffix(domain, "_ble"):
			return ProtocolBluetooth
		}
	}
	for _, c := range r.Connections {
		if len(c) == 0 {
			continue
		}
		switch c[0] {
		case "zigbee":
			return ProtocolZigbee
		case "bluetooth":
			return ProtocolBluetooth
		case "mac":
			return ProtocolIP
		}
	}
	return ProtocolOther
}

// text keeps printable characters only and cuts at max runes ("" when empty).
func text(s *string, limit int) string {
	if s == nil {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		// outside the BMP a rune is 2 UTF-16 units: dropped so that the backend limits hold
		if unicode.IsControl(r) || r == utf8.RuneError || r > 0xFFFF {
			return -1
		}
		return r
	}, *s)
	clean = strings.TrimSpace(clean)
	if utf8.RuneCountInString(clean) > limit {
		clean = strings.TrimSpace(string([]rune(clean)[:limit]))
	}
	return clean
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// String describes the settings without the token.
func (c Config) String() string {
	return fmt.Sprintf("Home Assistant %s (token set)", strings.TrimSpace(c.URL))
}
