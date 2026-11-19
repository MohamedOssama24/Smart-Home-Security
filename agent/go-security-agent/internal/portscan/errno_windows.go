//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

// Winsock error codes.
const (
	wsaeConnRefused = syscall.Errno(10061)
	wsaeConnReset   = syscall.Errno(10054) // ICMP port unreachable on a connected UDP socket
	wsaeHostUnreach = syscall.Errno(10065)
	wsaeNetUnreach  = syscall.Errno(10051)
)

// isRefused: the host answered with a reset (TCP) or an ICMP port unreachable (connected UDP socket).
func isRefused(err error) bool {
	return errors.Is(err, wsaeConnRefused) || errors.Is(err, wsaeConnReset) || errors.Is(err, syscall.ECONNREFUSED)
}

func isUnreachable(err error) bool {
	return errors.Is(err, wsaeHostUnreach) || errors.Is(err, wsaeNetUnreach)
}
