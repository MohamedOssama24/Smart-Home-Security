package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Install creates the "shsc" system user, gives it the state directory, writes the systemd
// unit and starts the service.
func Install(c Config, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	unit, err := SystemdUnit(c)
	if err != nil {
		return err
	}
	if err := checkExecutable(c.Executable); err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running on this system; start the agent with your init system: shsc-agent run --state-dir " + c.StateDir)
	}
	u, err := ensureUser()
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return err
	}
	if err := chownTree(c.StateDir, uid, gid); err != nil {
		return fmt.Errorf("give the state directory to %s: %w", ServiceUser, err)
	}
	if err := os.Chmod(c.StateDir, 0o700); err != nil {
		return err
	}
	if err := writeRootFile(UnitPath, unit); err != nil {
		return fmt.Errorf("write %s: %w", UnitPath, err)
	}
	if _, err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := run("systemctl", "enable", "--now", Name); err != nil {
		return err
	}
	say(out, "Service %s installed and started (user %s, only CAP_NET_RAW).", Name, ServiceUser)
	say(out, "Logs: journalctl -u %s", Name)
	return nil
}

func ensureUser() (*user.User, error) {
	if u, err := user.Lookup(ServiceUser); err == nil {
		return u, nil
	}
	nologin := "/usr/sbin/nologin"
	if _, err := os.Stat(nologin); err != nil {
		nologin = "/sbin/nologin"
	}
	if _, err := run("useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", nologin, ServiceUser); err != nil {
		// BusyBox systems (Alpine) have adduser instead of useradd
		if _, err2 := run("adduser", "-S", "-D", "-H", "-s", nologin, ServiceUser); err2 != nil {
			return nil, fmt.Errorf("create the system user %s: %w", ServiceUser, err)
		}
	}
	return user.Lookup(ServiceUser)
}

// Uninstall stops and removes the service. The identity and the system user are kept.
func Uninstall(c Config, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(UnitPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("service %s is not installed", Name)
	}
	if _, err := run("systemctl", "disable", "--now", Name); err != nil {
		return err
	}
	if err := os.Remove(UnitPath); err != nil {
		return err
	}
	if _, err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	say(out, "Service %s removed. The identity is still in %s (delete it to forget this agent).", Name, c.StateDir)
	return nil
}

// Start starts the installed service.
func Start() error {
	if err := requireRoot(); err != nil {
		return err
	}
	_, err := run("systemctl", "start", Name)
	return err
}

// Stop stops the installed service.
func Stop() error {
	if err := requireRoot(); err != nil {
		return err
	}
	_, err := run("systemctl", "stop", Name)
	return err
}

// Status returns the systemd state of the service (active, inactive, failed...).
func Status() (string, error) {
	if _, err := os.Stat(UnitPath); errors.Is(err, os.ErrNotExist) {
		return "not installed", nil
	}
	out, _ := run("systemctl", "is-active", Name) // non-zero exit for inactive states
	return strings.TrimSpace(out), nil
}
