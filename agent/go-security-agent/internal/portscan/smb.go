package portscan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SMB: only the NEGOTIATE exchange (dialect and signing), never a session setup, so no
// credential and no anonymous login are ever tried. SMB1 support is checked with a second
// NEGOTIATE in the SMB1 format, which is answered before any authentication.

var smb2Dialects = []uint16{0x0202, 0x0210, 0x0300, 0x0302}

const (
	smb2Magic      = "\xfeSMB"
	smb1Magic      = "\xffSMB"
	smbNegotiate1  = 0x72
	maxSMBResponse = 64 << 10
)

// smb2NegotiateRequest is a NetBIOS session message with an SMB2 NEGOTIATE (dialects 2.0.2-3.0.2).
func smb2NegotiateRequest() []byte {
	header := make([]byte, 64)
	copy(header, smb2Magic)
	binary.LittleEndian.PutUint16(header[4:], 64) // structure size
	binary.LittleEndian.PutUint16(header[14:], 1) // credits requested
	// command 0 = NEGOTIATE, message id 0
	body := make([]byte, 36, 36+2*len(smb2Dialects))
	binary.LittleEndian.PutUint16(body[0:], 36)
	binary.LittleEndian.PutUint16(body[2:], uint16(len(smb2Dialects)))
	binary.LittleEndian.PutUint16(body[4:], 1) // signing enabled
	_, _ = rand.Read(body[12:28])              // client GUID
	for _, d := range smb2Dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	return netbios(append(header, body...))
}

// smb1NegotiateRequest offers the single dialect "NT LM 0.12".
func smb1NegotiateRequest() []byte {
	header := make([]byte, 32)
	copy(header, smb1Magic)
	header[4] = smbNegotiate1
	header[9] = 0x18                                   // flags: canonical paths, case insensitive
	binary.LittleEndian.PutUint16(header[10:], 0xC801) // flags2: unicode, NT status, long names
	dialects := append([]byte{0x02}, "NT LM 0.12\x00"...)
	body := []byte{0} // word count
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dialects)))
	return netbios(append(header, append(body, dialects...)...))
}

func netbios(msg []byte) []byte {
	return append([]byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// readNetBIOS reads one session message (bounded).
func readNetBIOS(conn net.Conn) ([]byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	n := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if head[0] != 0 || n > maxSMBResponse {
		return nil, fmt.Errorf("not an SMB session message")
	}
	msg := make([]byte, n)
	_, err := io.ReadFull(conn, msg)
	return msg, err
}

// smb2Negotiated parses an SMB2 NEGOTIATE response.
func smb2Negotiated(msg []byte) (dialect uint16, securityMode uint16, ok bool) {
	if len(msg) < 64+6 || !bytes.HasPrefix(msg, []byte(smb2Magic)) ||
		binary.LittleEndian.Uint32(msg[8:]) != 0 || binary.LittleEndian.Uint16(msg[12:]) != 0 {
		return 0, 0, false
	}
	body := msg[64:]
	if binary.LittleEndian.Uint16(body[0:]) != 65 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint16(body[4:]), binary.LittleEndian.Uint16(body[2:]), true
}

// smb1Accepted reports whether an SMB1 NEGOTIATE response accepted the offered dialect.
func smb1Accepted(msg []byte) bool {
	if len(msg) < 32+3 || !bytes.HasPrefix(msg, []byte(smb1Magic)) || msg[4] != smbNegotiate1 ||
		binary.LittleEndian.Uint32(msg[5:]) != 0 {
		return false
	}
	return msg[32] > 0 && binary.LittleEndian.Uint16(msg[33:]) != 0xFFFF
}

func (h *hostScan) smbExchange(ctx context.Context, port int, request []byte) []byte {
	conn, err := h.dial(ctx, port)
	if err != nil {
		return nil
	}
	defer conn.Close()
	if _, err := conn.Write(request); err != nil {
		return nil
	}
	msg, err := readNetBIOS(conn)
	if err != nil {
		return nil
	}
	return msg
}

func (h *hostScan) smbService(ctx context.Context, port int) *Service {
	dialect, mode, ok := smb2Negotiated(h.smbExchange(ctx, port, smb2NegotiateRequest()))
	smb1 := smb1Accepted(h.smbExchange(ctx, port, smb1NegotiateRequest()))
	if !ok && !smb1 {
		return nil
	}
	s := confirmed("smb")
	s.Evidence["smb1"] = smb1
	if ok {
		s.Version = fmt.Sprintf("%d.%d.%d", dialect>>8, dialect>>4&0xF, dialect&0xF)
		s.Evidence["dialect"] = s.Version
		s.Evidence["signingEnabled"] = mode&0x1 != 0
		s.Evidence["signingRequired"] = mode&0x2 != 0
	} else {
		s.Version = "1"
	}
	return s
}
