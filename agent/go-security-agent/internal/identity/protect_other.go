//go:build !windows

package identity

import (
	"bytes"
	"errors"
	"os"
)

// On Linux and macOS the key is protected by file permissions: directory 0700 and files 0600,
// owned by the service user (set by "shsc-agent service install").

func protectKey(plain []byte) ([]byte, error) {
	return plain, nil
}

func unprotectKey(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte(dpapiMagic)) {
		return nil, errors.New("the key is protected with Windows DPAPI and cannot be used on this system")
	}
	return data, nil
}

func secureDir(dir string) error {
	return os.Chmod(dir, 0o700)
}
