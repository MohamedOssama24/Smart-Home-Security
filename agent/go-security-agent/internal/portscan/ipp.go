package portscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/netip"
)

// IPP: Get-Printer-Attributes (RFC 8011 §4.2.5), the public operation every client uses to
// learn what a printer is. No job is submitted and no other operation is sent.

const (
	ippGetPrinterAttributes = 0x000B
	ippEndTag               = 0x03
	ippOperationTag         = 0x01
)

var ippAttributes = []string{"printer-make-and-model", "printer-name", "printer-info", "printer-firmware-string-version"}

func ippAttribute(buf []byte, tag byte, name, value string) []byte {
	buf = append(buf, tag)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(name)))
	buf = append(buf, name...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(value)))
	return append(buf, value...)
}

// ippRequest builds a Get-Printer-Attributes request for printerURI.
func ippRequest(printerURI string) []byte {
	buf := []byte{1, 1} // IPP/1.1
	buf = binary.BigEndian.AppendUint16(buf, ippGetPrinterAttributes)
	buf = binary.BigEndian.AppendUint32(buf, 1)
	buf = append(buf, ippOperationTag)
	buf = ippAttribute(buf, 0x47, "attributes-charset", "utf-8")
	buf = ippAttribute(buf, 0x48, "attributes-natural-language", "en")
	buf = ippAttribute(buf, 0x45, "printer-uri", printerURI)
	for i, a := range ippAttributes {
		name := "requested-attributes"
		if i > 0 {
			name = "" // additional value of the same attribute
		}
		buf = ippAttribute(buf, 0x44, name, a)
	}
	return append(buf, ippEndTag)
}

// ippResponse parses the status code and the first value of each attribute.
func ippResponse(data []byte) (uint16, map[string]string, error) {
	if len(data) < 9 {
		return 0, nil, errors.New("IPP response too short")
	}
	status := binary.BigEndian.Uint16(data[2:])
	attrs := map[string]string{}
	i, last := 8, ""
	for i < len(data) {
		tag := data[i]
		i++
		if tag == ippEndTag {
			return status, attrs, nil
		}
		if tag <= 0x0F { // other delimiter (group) tags
			continue
		}
		if i+2 > len(data) {
			break
		}
		nameLen := int(binary.BigEndian.Uint16(data[i:]))
		i += 2
		if i+nameLen+2 > len(data) {
			break
		}
		name := string(data[i : i+nameLen])
		i += nameLen
		valueLen := int(binary.BigEndian.Uint16(data[i:]))
		i += 2
		if i+valueLen > len(data) {
			break
		}
		if name == "" {
			name = last
		} else {
			last = name
		}
		if _, seen := attrs[name]; !seen && tag >= 0x30 { // text/name/keyword/uri values
			attrs[name] = string(data[i : i+valueLen])
		}
		i += valueLen
	}
	return 0, nil, errors.New("truncated IPP response")
}

func (h *hostScan) ippService(ctx context.Context, port int) *Service {
	hostPort := netip.AddrPortFrom(h.ip, uint16(port)).String()
	for _, path := range []string{"/ipp/print", "/"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL("http", port)+path,
			bytes.NewReader(ippRequest("ipp://"+hostPort+path)))
		if err != nil {
			return nil
		}
		req.Header.Set("Content-Type", "application/ipp")
		req.Header.Set("User-Agent", h.o.UserAgent)
		resp, err := h.httpClient(nil).Do(req)
		if err != nil {
			return nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		status, attrs, err := ippResponse(body)
		if resp.StatusCode != http.StatusOK || err != nil {
			// an HTTP server on the IPP port: still a confirmed web service
			return h.httpService(ctx, port, "http", false)
		}
		s := confirmed("ipp")
		s.Evidence["statusCode"] = int(status)
		for key, field := range map[string]string{"printer-make-and-model": "makeAndModel", "printer-name": "name",
			"printer-info": "info", "printer-firmware-string-version": "firmware"} {
			if v := clean(attrs[key], 128); v != "" {
				s.Evidence[field] = v
			}
		}
		if v, ok := s.Evidence["makeAndModel"].(string); ok {
			s.Product = v
		}
		if v, ok := s.Evidence["firmware"].(string); ok {
			s.Version = v
		}
		return s
	}
	return nil
}
