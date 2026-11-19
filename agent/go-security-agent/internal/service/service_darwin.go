package service

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const launchdTarget = "system/" + LaunchdLabel

// Install writes the launchd daemon and loads it. The daemon runs as root because raw ARP
// on macOS needs a BPF device; the state directory stays root-only (0700).
func Install(c Config, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	plist, err := LaunchdPlist(c)
	if err != nil {
		return err
	}
	if err := checkExecutable(c.Executable); err != nil {
		return err
	}
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(c.StateDir, 0o700); err != nil {
		return err
	}
	if err := writeRootFile(PlistPath, plist); err != nil {
		return fmt.Errorf("write %s: %w", PlistPath, err)
	}
	if _, err := run("launchctl", "bootstrap", "system", PlistPath); err != nil {
		return err
	}
	say(out, "Daemon %s installed and started. Logs: /Library/Logs/shsc-agent.log", LaunchdLabel)
	return nil
}

// Uninstall unloads and removes the daemon. The identity is kept.
func Uninstall(c Config, out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(PlistPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("daemon %s is not installed", LaunchdLabel)
	}
	_, _ = run("launchctl", "bootout", launchdTarget) // already unloaded is fine
	if err := os.Remove(PlistPath); err != nil {
		return err
	}
	say(out, "Daemon %s removed. The identity is still in %s (delete it to forget this agent).", LaunchdLabel, c.StateDir)
	return nil
}

// Start loads the daemon (it starts at load).
func Start() error {
	if err := requireRoot(); err != nil {
		return err
	}
	_, err := run("launchctl", "bootstrap", "system", PlistPath)
	return err
}

// Stop unloads the daemon (KeepAlive would otherwise restart it).
func Stop() error {
	if err := requireRoot(); err != nil {
		return err
	}
	_, err := run("launchctl", "bootout", launchdTarget)
	return err
}

// Status reports whether the daemon is loaded.
func Status() (string, error) {
	if _, err := os.Stat(PlistPath); errors.Is(err, os.ErrNotExist) {
		return "not installed", nil
	}
	if _, err := run("launchctl", "print", launchdTarget); err != nil {
		return "not loaded", nil
	}
	return "loaded", nil
}
