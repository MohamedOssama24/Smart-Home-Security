//go:build !windows

package identities

import "context"

func readEvents(context.Context, DirectoryConfig, string, int, func([]byte)) error {
	return ErrUnsupported
}
