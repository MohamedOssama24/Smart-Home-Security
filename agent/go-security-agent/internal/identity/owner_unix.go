//go:build linux || darwin

package identity

import (
	"os"
	"path/filepath"
	"syscall"
)

// MatchOwner gives every file of the state directory to the owner of the directory. Commands
// run with sudo (rotate-key, diagnose) would otherwise leave root-owned files that the
// service user cannot read. No-op when not running as root.
func (s Store) MatchOwner() error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, err := os.Stat(s.Dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return nil
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Lchown(filepath.Join(s.Dir, e.Name()), int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	return nil
}
