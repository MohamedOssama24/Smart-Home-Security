//go:build !linux && !windows

package discovery

import "errors"

// neighbourTable6 is not read on this system: only the all-nodes echo is used.
func neighbourTable6(int) ([]neighbour, error) {
	return nil, errors.New("IPv6 neighbour table not supported on this system")
}
