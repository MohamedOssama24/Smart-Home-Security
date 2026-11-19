//go:build linux || darwin

package service

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// IsWindowsService is always false outside Windows.
func IsWindowsService() (bool, error) {
	return false, nil
}

// RunWindowsService is only available on Windows.
func RunWindowsService(func(context.Context) error) error {
	return ErrNotSupported
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (sudo)")
	}
	return nil
}

// checkExecutable refuses binaries that the service could not run (home directories are
// hidden by ProtectHome) or that a non-root user could replace (the service would then run
// someone else's code with CAP_NET_RAW).
func checkExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("the agent binary path must be absolute: %s", path)
	}
	for _, private := range []string{"/home/", "/root/", "/Users/"} {
		if strings.HasPrefix(path, private) {
			return fmt.Errorf("install the binary outside home directories first, e.g. sudo install -m 0755 %s /usr/local/bin/shsc-agent", path)
		}
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if err := rootOwnedNotWritable(p, info); err != nil {
			return err
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

func rootOwnedNotWritable(path string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if ok && st.Uid != 0 {
		return fmt.Errorf("%s must be owned by root", path)
	}
	// sticky directories such as /tmp are still unsafe for a service binary
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be writable by group or others", path)
	}
	return nil
}

// chownTree gives the state directory to the service user.
func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

func writeRootFile(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// run executes a system tool with fixed arguments (no shell) and returns its output.
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func say(out io.Writer, format string, args ...any) {
	fmt.Fprintf(out, format+"\n", args...)
}
