package portscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const testAgent = "SmartHomeSecurityCheck-Agent/test"

func httpPort(t *testing.T, s *httptest.Server) int {
	t.Helper()
	u, _ := url.Parse(s.URL)
	port, _ := strconv.Atoi(u.Port())
	return port
}

// smbMock answers the SMB2 NEGOTIATE with dialect 3.0.2 and signing required; SMB1 is refused
// (connection closed). It records every SMB command it receives.
type smbMock struct {
	mu       sync.Mutex
	commands []string
}

func (s *smbMock) serve(conn net.Conn) {
	msg, err := readNetBIOS(conn)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case bytes.HasPrefix(msg, []byte(smb2Magic)) && len(msg) >= 64:
		s.commands = append(s.commands, "SMB2:"+strconv.Itoa(int(binary.LittleEndian.Uint16(msg[12:]))))
		resp := make([]byte, 64+65)
		copy(resp, smb2Magic)
		binary.LittleEndian.PutUint16(resp[4:], 64)
		binary.LittleEndian.PutUint16(resp[64:], 65)
		binary.LittleEndian.PutUint16(resp[66:], 0x03) // signing enabled + required
		binary.LittleEndian.PutUint16(resp[68:], 0x0302)
		_, _ = conn.Write(netbios(resp))
	case bytes.HasPrefix(msg, []byte(smb1Magic)) && len(msg) > 4:
		s.commands = append(s.commands, "SMB1:"+strconv.Itoa(int(msg[4])))
	}
}

func TestServiceDetectionAndPolicy(t *testing.T) {
	ssh := newTCPMock(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 MOCK\r\n"))
		_, _ = io.Copy(io.Discard, c)
	})
	telnet := newTCPMock(t, func(c net.Conn) {
		_, _ = c.Write(append([]byte{0xFF, 0xFD, 0x01}, "MOCK login: "...))
		_, _ = io.Copy(io.Discard, c)
	})
	ftp := newTCPMock(t, func(c net.Conn) {
		_, _ = c.Write([]byte("220 MOCK FTP server ready\r\n"))
		_, _ = io.Copy(io.Discard, c)
	})
	rtsp := newTCPMock(t, func(c net.Conn) {
		buf := make([]byte, 2048)
		var req []byte
		for !bytes.Contains(req, []byte("\r\n\r\n")) {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			req = append(req, buf[:n]...)
		}
		_, _ = c.Write([]byte("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: MOCK-Camera/2.1\r\nPublic: OPTIONS, DESCRIBE, PLAY\r\n\r\n"))
	})
	smb := &smbMock{}
	smbPort := newTCPMock(t, smb.serve)
	mqtt := newTCPMock(t, nil)

	var mu sync.Mutex
	var httpRequests []string
	record := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		httpRequests = append(httpRequests, r.Method+" "+r.URL.Path+" "+r.UserAgent())
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.Header().Set("Server", "lighttpd/1.4.59")
		_, _ = w.Write([]byte(`<html><title> MOCK
 Router </title><form><input type="password" name="p"></form></html>`))
	}))
	t.Cleanup(web.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		http.Redirect(w, r, "https://other-host.invalid/", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = w.Write([]byte("<title>MOCK NAS</title>"))
	}))
	t.Cleanup(secure.Close)
	ipp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		record(r)
		if r.Header.Get("Content-Type") != "application/ipp" || len(body) < 4 ||
			binary.BigEndian.Uint16(body[2:]) != ippGetPrinterAttributes {
			http.Error(w, "unexpected operation", http.StatusBadRequest)
			return
		}
		resp := []byte{2, 0, 0, 0, 0, 0, 0, 1, 0x04}
		resp = ippAttribute(resp, 0x41, "printer-make-and-model", "MOCK LaserJet 100")
		resp = ippAttribute(resp, 0x42, "printer-name", "mock-printer")
		resp = ippAttribute(resp, 0x21, "printer-state", "\x00\x00\x00\x03")
		w.Header().Set("Content-Type", "application/ipp")
		_, _ = w.Write(append(resp, ippEndTag))
	}))
	t.Cleanup(ipp.Close)

	services := map[int]string{ssh.port: "ssh", telnet.port: "telnet", ftp.port: "ftp", rtsp.port: "rtsp",
		smbPort.port: "smb", mqtt.port: "mqtt", httpPort(t, web): "http", httpPort(t, redirect): "http",
		httpPort(t, secure): "https", httpPort(t, ipp): "ipp"}
	var ports []int
	for p := range services {
		ports = append(ports, p)
	}
	sortInts(ports)
	results, sums, warnings := Run(context.Background(), []netip.Addr{loopback}, Options{
		Profile: Profile{TCP: ports}, Lists: testLists(services), Limits: fastLimits(), InScope: onlyLoopback,
		UserAgent: testAgent,
	})
	if len(warnings) != 0 || sums[0].TCP.Open != len(services) {
		t.Fatalf("warnings %v, summary %+v", warnings, sums)
	}
	byPort := map[int]*Service{}
	for _, r := range results {
		byPort[r.Port] = r.Service
	}

	if s := byPort[ssh.port]; s.Name != "ssh" || s.Status != StatusConfirmed || s.Product != "OpenSSH" || s.Version != "9.6p1" {
		t.Errorf("ssh %+v", s)
	}
	if s := byPort[telnet.port]; s.Name != "telnet" || s.Status != StatusConfirmed || s.Evidence["banner"] != "MOCK login:" {
		t.Errorf("telnet %+v", s)
	}
	if s := byPort[ftp.port]; s.Name != "ftp" || s.Status != StatusConfirmed {
		t.Errorf("ftp %+v", s)
	}
	if s := byPort[rtsp.port]; s.Name != "rtsp" || s.Product != "MOCK-Camera" || s.Version != "2.1" ||
		s.Evidence["authRequired"] != true || s.Evidence["methods"] != "OPTIONS, DESCRIBE, PLAY" {
		t.Errorf("rtsp %+v", s)
	}
	if s := byPort[smbPort.port]; s.Name != "smb" || s.Version != "3.0.2" || s.Evidence["signingRequired"] != true ||
		s.Evidence["smb1"] != false {
		t.Errorf("smb %+v", s)
	}
	if s := byPort[mqtt.port]; s.Name != "mqtt" || s.Status != StatusProbable {
		t.Errorf("mqtt %+v", s)
	}
	if s := byPort[httpPort(t, web)]; s.Name != "http" || s.Product != "lighttpd" || s.Version != "1.4.59" ||
		s.Evidence["title"] != "MOCK Router" || s.Evidence["loginForm"] != true {
		t.Errorf("http %+v", s)
	}
	if s := byPort[httpPort(t, redirect)]; s.Evidence["status"] != http.StatusFound || s.Evidence["redirectsToHttps"] != true {
		t.Errorf("redirect %+v", s)
	}
	s := byPort[httpPort(t, secure)]
	if s.Name != "https" || s.Status != StatusConfirmed || s.Product != "nginx" || s.Evidence["title"] != "MOCK NAS" {
		t.Errorf("https %+v", s)
	}
	if versions, _ := s.TLS["versions"].([]string); len(versions) == 0 || versions[0] != "TLS1.3" ||
		s.TLS["subject"] == nil || s.TLS["notAfter"] == nil {
		t.Errorf("tls %+v", s.TLS)
	}
	if s := byPort[httpPort(t, ipp)]; s.Name != "ipp" || s.Product != "MOCK LaserJet 100" || s.Evidence["name"] != "mock-printer" {
		t.Errorf("ipp %+v", s)
	}

	// --- policy: nothing but the allowed read-only requests reached the MOCK devices -------
	for name, m := range map[string]*tcpMock{"telnet": telnet, "mqtt": mqtt, "ssh": ssh} {
		if got := m.got(); len(got) != 0 {
			t.Errorf("%s: the agent sent %q (banners are read passively)", name, got)
		}
	}
	if got := strings.ToUpper(string(ftp.got())); got != "" {
		t.Errorf("ftp: the agent sent %q (no USER, no anonymous login)", got)
	}
	req := string(rtsp.got())
	if !strings.HasPrefix(req, "OPTIONS rtsp://127.0.0.1:"+strconv.Itoa(rtsp.port)+"/ RTSP/1.0\r\n") ||
		strings.Contains(req, "DESCRIBE") || strings.Contains(req, "PLAY") || strings.Contains(req, "SETUP") ||
		strings.Contains(strings.ToLower(req), "authorization") {
		t.Errorf("rtsp request %q", req)
	}
	smb.mu.Lock()
	for _, c := range smb.commands {
		if c != "SMB2:0" && c != "SMB1:114" { // NEGOTIATE only, never SESSION_SETUP
			t.Errorf("SMB command %s sent", c)
		}
	}
	smb.mu.Unlock()
	mu.Lock()
	for _, r := range httpRequests {
		if !strings.HasSuffix(r, " "+testAgent) || !(strings.HasPrefix(r, "GET / ") || strings.HasPrefix(r, "POST /ipp/print ")) {
			t.Errorf("HTTP request %q", r)
		}
	}
	if len(httpRequests) != 4 {
		t.Errorf("HTTP requests %v (redirects must not be followed)", httpRequests)
	}
	mu.Unlock()
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func TestBannerIdentification(t *testing.T) {
	for banner, want := range map[string]string{
		"SSH-2.0-dropbear_2020.81\r\n":      "ssh dropbear 2020.81",
		"RFB 003.008\n":                     "vnc  3.8",
		"220 mail.mock ESMTP Postfix\r\n":   "smtp  ",
		"+OK MOCK POP3 ready\r\n":           "pop3  ",
		"\x00\x01garbage\x7f with controls": "unknown  ",
	} {
		s := identifyBanner("", []byte(banner))
		if got := s.Name + " " + s.Product + " " + s.Version; got != want {
			t.Errorf("%q: got %q, want %q", banner, got, want)
		}
		if b, _ := s.Evidence["banner"].(string); strings.ContainsAny(b, "\x00\x01\x7f\r\n") {
			t.Errorf("banner not sanitized: %q", b)
		}
	}
	if got := clean(strings.Repeat("é", 400), 101); len(got) > 101 || !strings.HasPrefix(got, "é") {
		t.Fatalf("clean: %d bytes", len(got))
	}
}
