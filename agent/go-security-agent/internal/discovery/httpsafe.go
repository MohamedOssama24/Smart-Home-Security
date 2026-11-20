package discovery

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Fetching URLs announced by devices (SSDP LOCATION, UPnP control URLs) is a classic SSRF
// vector: a device could point the agent at any host. A URL is followed only when:
//   - its scheme is http and it has no user information;
//   - its host is an IP literal equal to the device that announced it (no name resolution);
//   - that address belongs to an authorized target.
//
// The client never uses a proxy, never follows redirects, dials only that address, waits
// at most 3 s and reads at most 256 KB. XML is parsed with encoding/xml, which does not
// resolve external entities.

const (
	httpTimeout  = 3 * time.Second
	maxHTTPBytes = 256 << 10
)

var errUnsafeURL = errors.New("URL refused: not the announcing device or not in scope")

// safeURL resolves ref against base and checks it designates the device itself.
func safeURL(base *url.URL, ref string, device netip.Addr) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return nil, err
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.Scheme != "http" || u.User != nil || u.Opaque != "" {
		return nil, errUnsafeURL
	}
	host, err := netip.ParseAddr(u.Hostname())
	if err != nil || host.Unmap() != device.Unmap() {
		return nil, errUnsafeURL
	}
	return u, nil
}

// deviceClient returns an HTTP client that can only reach device.
func deviceClient(device netip.Addr) *http.Client {
	dialer := &net.Dialer{Timeout: httpTimeout}
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if ip, err := netip.ParseAddr(host); err != nil || ip.Unmap() != device.Unmap() {
					return nil, errUnsafeURL
				}
				return dialer.DialContext(ctx, network, addr)
			},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: httpTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// httpStatusError is a non-200 answer.
type httpStatusError struct {
	Status int
	Header http.Header
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP status %d", e.Status) }

// readLimited reads a 200 answer of at most maxHTTPBytes.
func readLimited(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPBytes))
		return nil, &httpStatusError{Status: resp.StatusCode, Header: resp.Header}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHTTPBytes {
		return nil, errors.New("answer larger than 256 KB")
	}
	return data, nil
}

// upnpRoot is a UPnP (or TR-064) device description.
type upnpRoot struct {
	URLBase string     `xml:"URLBase"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	DeviceType   string `xml:"deviceType"`
	FriendlyName string `xml:"friendlyName"`
	Manufacturer string `xml:"manufacturer"`
	ModelName    string `xml:"modelName"`
	ModelNumber  string `xml:"modelNumber"`
	// non-standard elements used by several vendors for the firmware version (M20)
	FirmwareVersion string        `xml:"firmwareVersion"`
	SoftwareVersion string        `xml:"softwareVersion"`
	Icons           []upnpIcon    `xml:"iconList>icon"` // M23
	Services        []upnpService `xml:"serviceList>service"`
	Devices         []upnpDevice  `xml:"deviceList>device"`
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

// walk visits the device and its embedded devices (bounded depth).
func (d *upnpDevice) walk(depth int, visit func(*upnpDevice)) {
	if depth > 4 {
		return
	}
	visit(d)
	for i := range d.Devices {
		d.Devices[i].walk(depth+1, visit)
	}
}

// fetchDescription downloads and parses a device description.
func fetchDescription(ctx context.Context, client *http.Client, u *url.URL) (upnpRoot, error) {
	var root upnpRoot
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return root, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return root, err
	}
	data, err := readLimited(resp)
	if err != nil {
		return root, err
	}
	err = xml.NewDecoder(bytes.NewReader(data)).Decode(&root)
	return root, err
}

// soapCall invokes a read-only UPnP/TR-064 action and returns the leaf values of the answer
// by element name. do sends the request (plain or with digest authentication).
func soapCall(ctx context.Context, do func(*http.Request) (*http.Response, error), u *url.URL, service,
	action string, args map[string]string) (map[string]string, error) {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	fmt.Fprintf(&body, `<u:%s xmlns:u="%s">`, action, xmlEscape(service))
	for k, v := range args {
		fmt.Fprintf(&body, "<%s>%s</%s>", k, xmlEscape(v), k)
	}
	fmt.Fprintf(&body, `</u:%s></s:Body></s:Envelope>`, action)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body.String()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, service, action))
	resp, err := do(req)
	if err != nil {
		return nil, err
	}
	data, err := readLimited(resp)
	if err != nil {
		return nil, err
	}
	return xmlLeaves(data)
}

// xmlLeaves maps the local name of every leaf element to its text.
func xmlLeaves(data []byte) (map[string]string, error) {
	out := map[string]string{}
	d := xml.NewDecoder(bytes.NewReader(data))
	var name string
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name = t.Name.Local
			text.Reset()
		case xml.CharData:
			if text.Len() < 1024 {
				text.Write(t)
			}
		case xml.EndElement:
			if name == t.Name.Local {
				out[name] = strings.TrimSpace(text.String())
			}
			name = ""
		}
	}
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
