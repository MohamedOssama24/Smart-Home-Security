package portscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Service detection of the open TCP ports (docs/08 §3). Every probe dials only the scanned
// host, waits for the rate limits, has a deadline and reads a bounded number of bytes.

const (
	bannerWait    = 2 * time.Second
	probeDeadline = 4 * time.Second
	maxHTTPBody   = 64 << 10
	maxHeaderRead = 4 << 10
)

type probeKind int

const (
	kindBanner probeKind = iota // read what the service says first, send nothing
	kindHTTP
	kindTLS
	kindRTSP
	kindSMB
	kindIPP
	kindNone // the open port is the only safe evidence (e.g. MQTT: no CONNECT is sent)
)

func kindOf(name string) probeKind {
	switch name {
	case "http", "upnp", "tr069", "wsd", "http-proxy":
		return kindHTTP
	case "https", "smtps", "imaps", "pop3s", "ldaps", "mqtts", "docker-tls", "winrm-tls", "sips", "cast":
		return kindTLS
	case "rtsp":
		return kindRTSP
	case "smb":
		return kindSMB
	case "ipp":
		return kindIPP
	case "mqtt":
		return kindNone
	}
	return kindBanner
}

var errOffHost = errors.New("connection refused: not the scanned host")

// detect identifies the service of an open TCP port; never nil.
func (h *hostScan) detect(ctx context.Context, port int) *Service {
	name := h.o.Lists.ServiceOf(TCP, port)
	var svc *Service
	switch kindOf(name) {
	case kindHTTP:
		svc = h.httpService(ctx, port, name, false)
	case kindTLS:
		svc = h.tlsService(ctx, port, name)
	case kindRTSP:
		svc = h.rtspService(ctx, port)
	case kindSMB:
		svc = h.smbService(ctx, port)
	case kindIPP:
		svc = h.ippService(ctx, port)
	case kindNone:
	default:
		svc = h.bannerService(ctx, port, name)
	}
	if svc == nil {
		svc = probable(name)
	}
	return svc
}

// probable is a service deduced from the port number only.
func probable(name string) *Service {
	if name == "" {
		name = "unknown"
	}
	return &Service{Name: name, Status: StatusProbable, Confidence: "LOW"}
}

func confirmed(name string) *Service {
	return &Service{Name: name, Status: StatusConfirmed, Confidence: "HIGH", Evidence: map[string]any{}}
}

// dial opens a TCP connection to the scanned host, after the rate limits.
func (h *hostScan) dial(ctx context.Context, port int) (net.Conn, error) {
	if !h.wait(ctx) {
		return nil, context.Canceled
	}
	d := net.Dialer{Timeout: h.lim.Timeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(h.ip, uint16(port)).String())
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(probeDeadline))
	return conn, nil
}

// readUntil reads at most limit bytes, until done reports a complete answer or the deadline.
func readUntil(conn net.Conn, limit int, wait time.Duration, done func([]byte) bool) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 0, min(limit, 4096))
	chunk := make([]byte, 1024)
	for len(buf) < limit {
		n, err := conn.Read(chunk[:min(len(chunk), limit-len(buf))])
		buf = append(buf, chunk[:n]...)
		if err != nil || done != nil && done(buf) {
			break
		}
	}
	return buf
}

// --- passive banner -------------------------------------------------------------------

func (h *hostScan) bannerService(ctx context.Context, port int, name string) *Service {
	conn, err := h.dial(ctx, port)
	if err != nil {
		return nil
	}
	defer conn.Close()
	data := readUntil(conn, maxEvidenceBytes, bannerWait, func(b []byte) bool { return bytes.Contains(b, []byte("\n")) })
	if len(data) == 0 {
		return nil
	}
	return identifyBanner(name, data)
}

var rfb = regexp.MustCompile(`^RFB (\d{3})\.(\d{3})`)

// identifyBanner recognizes the protocol of a banner the service sent by itself.
func identifyBanner(name string, data []byte) *Service {
	if data[0] == 0xFF { // Telnet option negotiation (IAC): never answered
		s := confirmed("telnet")
		if text := clean(string(stripIAC(data)), maxEvidenceBytes); text != "" {
			s.Evidence["banner"] = text
		}
		return s
	}
	text := clean(string(data), maxEvidenceBytes)
	var s *Service
	switch {
	case strings.HasPrefix(text, "SSH-"):
		s = confirmed("ssh")
		fields := strings.SplitN(text, "-", 3)
		if len(fields) == 3 {
			software := strings.Fields(fields[2])
			if len(software) > 0 {
				s.Product, s.Version, _ = strings.Cut(software[0], "_")
			}
		}
	case rfb.MatchString(text):
		s = confirmed("vnc")
		m := rfb.FindStringSubmatch(text)
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		s.Version = fmt.Sprintf("%d.%d", major, minor)
	case strings.HasPrefix(text, "220"):
		upper := strings.ToUpper(text)
		switch {
		case strings.Contains(upper, "SMTP") || name == "smtp":
			s = confirmed("smtp")
		case strings.Contains(upper, "FTP") || name == "ftp":
			s = confirmed("ftp")
		default:
			s = probable(name)
			s.Confidence = "MEDIUM"
		}
	case strings.HasPrefix(text, "+OK"):
		s = confirmed("pop3")
	case strings.HasPrefix(text, "* OK"):
		s = confirmed("imap")
	case strings.HasPrefix(text, "HTTP/1."):
		s = confirmed("http")
	default:
		s = probable(name)
	}
	if s.Evidence == nil {
		s.Evidence = map[string]any{}
	}
	s.Evidence["banner"] = text
	return s
}

// stripIAC removes the Telnet commands (IAC sequences) from a banner.
func stripIAC(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); i++ {
		if b[i] != 0xFF {
			out = append(out, b[i])
			continue
		}
		if i+1 >= len(b) {
			break
		}
		switch b[i+1] {
		case 0xFA: // SB ... IAC SE
			end := bytes.Index(b[i+2:], []byte{0xFF, 0xF0})
			if end < 0 {
				return out
			}
			i += end + 3
		case 0xFB, 0xFC, 0xFD, 0xFE: // WILL WONT DO DONT <option>
			i += 2
		default:
			i++
		}
	}
	return out
}

// --- HTTP -----------------------------------------------------------------------------

var (
	titleRE     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	passwordRE  = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)
	productRE   = regexp.MustCompile(`^([A-Za-z][\w.\-]*)(?:/([\w.\-]+))?`)
	whitespaceR = regexp.MustCompile(`\s+`)
)

// httpClient reaches only the scanned host: no proxy, no redirect, no keep-alive, bounded.
func (h *hostScan) httpClient(tlsConf *tls.Config) *http.Client {
	dialer := &net.Dialer{Timeout: h.lim.Timeout}
	return &http.Client{
		Timeout: probeDeadline,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if ip, err := netip.ParseAddr(host); err != nil || ip.Unmap() != h.ip.Unmap() {
					return nil, errOffHost
				}
				if !h.wait(ctx) {
					return nil, context.Canceled
				}
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig:        tlsConf,
			DisableKeepAlives:      true,
			ResponseHeaderTimeout:  probeDeadline,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (h *hostScan) baseURL(scheme string, port int) string {
	return scheme + "://" + netip.AddrPortFrom(h.ip, uint16(port)).String()
}

// httpGet sends GET / and describes the answer (never follows a redirect).
func (h *hostScan) httpGet(ctx context.Context, port int, secure bool) map[string]any {
	scheme, conf := "http", (*tls.Config)(nil)
	if secure {
		scheme, conf = "https", &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10} //nolint:gosec // inspected, not trusted
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL(scheme, port)+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", h.o.UserAgent)
	req.Header.Set("Accept", "text/html,*/*")
	resp, err := h.httpClient(conf).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	ev := map[string]any{"status": resp.StatusCode}
	if server := clean(resp.Header.Get("Server"), 128); server != "" {
		ev["server"] = server
	}
	if m := titleRE.FindSubmatch(body); m != nil {
		if title := clean(whitespaceR.ReplaceAllString(string(m[1]), " "), 128); title != "" {
			ev["title"] = title
		}
	}
	if passwordRE.Match(body) {
		ev["loginForm"] = true
	}
	if auth := resp.Header.Get("WWW-Authenticate"); auth != "" {
		scheme, _, _ := strings.Cut(strings.TrimSpace(auth), " ")
		ev["authenticate"] = clean(scheme, 32)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := strings.ToLower(strings.TrimSpace(resp.Header.Get("Location")))
		ev["redirectsToHttps"] = strings.HasPrefix(location, "https://")
	}
	return ev
}

func (h *hostScan) httpService(ctx context.Context, port int, name string, secure bool) *Service {
	ev := h.httpGet(ctx, port, secure)
	if ev == nil {
		return h.bannerService(ctx, port, name)
	}
	s := confirmed("http")
	if secure {
		s.Name = "https"
	}
	s.Evidence = ev
	if server, ok := ev["server"].(string); ok {
		s.Product, s.Version = product(server)
	}
	return s
}

// product splits "lighttpd/1.4.59 (Linux)" into ("lighttpd", "1.4.59").
func product(server string) (string, string) {
	m := productRE.FindStringSubmatch(strings.TrimSpace(server))
	if m == nil {
		return "", ""
	}
	return m[1], m[2]
}

// --- TLS ------------------------------------------------------------------------------

var tlsVersions = []struct {
	id   uint16
	name string
}{{tls.VersionTLS13, "TLS1.3"}, {tls.VersionTLS12, "TLS1.2"}, {tls.VersionTLS11, "TLS1.1"}, {tls.VersionTLS10, "TLS1.0"}}

// tlsInfo makes one handshake per protocol version: supported versions and certificate.
// The certificate is inspected, never trusted; no data is exchanged after the handshake.
func (h *hostScan) tlsInfo(ctx context.Context, port int) map[string]any {
	var versions []string
	var cert *x509.Certificate
	for _, v := range tlsVersions {
		conn, err := h.dial(ctx, port)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: v.id, MaxVersion: v.id}) //nolint:gosec
		err = client.HandshakeContext(ctx)
		if err == nil {
			versions = append(versions, v.name)
			if certs := client.ConnectionState().PeerCertificates; cert == nil && len(certs) > 0 {
				cert = certs[0]
			}
		}
		_ = conn.Close()
	}
	if len(versions) == 0 {
		return nil
	}
	info := map[string]any{"versions": versions}
	if cert != nil {
		info["subject"] = clean(cert.Subject.String(), 200)
		info["issuer"] = clean(cert.Issuer.String(), 200)
		info["notAfter"] = cert.NotAfter.UTC().Format(time.RFC3339)
		info["expired"] = h.o.Now().After(cert.NotAfter)
		info["selfSigned"] = bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
		var names []string
		for _, n := range cert.DNSNames {
			if len(names) == 5 {
				break
			}
			names = append(names, clean(n, 100))
		}
		if len(names) > 0 {
			info["names"] = names
		}
	}
	return info
}

func (h *hostScan) tlsService(ctx context.Context, port int, name string) *Service {
	info := h.tlsInfo(ctx, port)
	if info == nil {
		return nil
	}
	if name == "https" || name == "" {
		if ev := h.httpGet(ctx, port, true); ev != nil {
			s := confirmed("https")
			s.Evidence, s.TLS = ev, info
			if server, ok := ev["server"].(string); ok {
				s.Product, s.Version = product(server)
			}
			return s
		}
	}
	// TLS confirmed; the protocol inside it is deduced from the port (e.g. MQTT over TLS)
	s := probable(name)
	s.Confidence = "MEDIUM"
	s.TLS = info
	return s
}

// --- RTSP -----------------------------------------------------------------------------

var rtspStatus = regexp.MustCompile(`^RTSP/1\.\d (\d{3})`)

// rtspService sends OPTIONS only: no DESCRIBE, no PLAY, no stream is opened.
func (h *hostScan) rtspService(ctx context.Context, port int) *Service {
	conn, err := h.dial(ctx, port)
	if err != nil {
		return nil
	}
	defer conn.Close()
	request := fmt.Sprintf("OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: %s\r\n\r\n",
		netip.AddrPortFrom(h.ip, uint16(port)), h.o.UserAgent)
	if _, err := conn.Write([]byte(request)); err != nil {
		return nil
	}
	data := readUntil(conn, maxHeaderRead, probeDeadline, func(b []byte) bool { return bytes.Contains(b, []byte("\r\n\r\n")) })
	m := rtspStatus.FindSubmatch(data)
	if m == nil {
		if len(data) > 0 {
			return identifyBanner("rtsp", data)
		}
		return nil
	}
	s := confirmed("rtsp")
	status, _ := strconv.Atoi(string(m[1]))
	s.Evidence["status"] = status
	if status == http.StatusUnauthorized {
		s.Evidence["authRequired"] = true
	}
	headers := parseHeaders(data)
	if server := clean(headers["server"], 128); server != "" {
		s.Evidence["server"] = server
		s.Product, s.Version = product(server)
	}
	if public := clean(headers["public"], 200); public != "" {
		s.Evidence["methods"] = public
	}
	return s
}

// parseHeaders reads "Name: value" lines (lower-case names).
func parseHeaders(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\r\n")[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return out
}

// clean makes a device-provided string safe to store: valid UTF-8, no control characters,
// at most n bytes.
func clean(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			if r == '\n' || r == '\r' || r == '\t' {
				return ' '
			}
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
