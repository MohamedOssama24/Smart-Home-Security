//go:build !windows

package portscan

import (
	"errors"
	"syscall"
)

// isRefused: the host answered with a reset (TCP) or an ICMP port unreachable (connected UDP socket).
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

func isUnreachable(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH)
}
