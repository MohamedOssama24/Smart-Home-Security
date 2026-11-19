// Package service installs and controls the agent as an operating system service
// (docs/03-AGENT-PROTOCOL.md §10), using only the platform tools and golang.org/x/sys:
//
//   - Linux: systemd unit, dedicated system user "shsc", only CAP_NET_RAW, sandboxing options;
//   - macOS: launchd daemon (root, needed for BPF);
//   - Windows: Windows Service as LocalService, automatic (delayed) start, restart on failure.
//
// The service runs "shsc-agent run". A revoked agent exits with ExitRevoked (Linux/macOS) or
// stops cleanly (Windows), so that the service manager does not restart it.
package service

import (
	"errors"
	"fmt"
	"strings"
)

// Names of the service on every platform.
const (
	Name         = "shsc-agent"
	DisplayName  = "Smart Home Security Check Agent"
	Description  = "Local agent of Smart Home Security Check: runs only the scans started by the owner from the dashboard."
	LaunchdLabel = "com.shsc.agent"
	UnitPath     = "/etc/systemd/system/shsc-agent.service"
	PlistPath    = "/Library/LaunchDaemons/com.shsc.agent.plist"
	ServiceUser  = "shsc"
	// Exit codes of "run" after which the service must not be restarted.
	ExitRevoked     = 3 // the agent was revoked from the dashboard
	ExitNotEnrolled = 4 // no identity in the state directory
)

// Config describes the installed service.
type Config struct {
	Executable string // absolute path of the agent binary
	StateDir   string // identity and queue directory
}

func (c Config) validate() error {
	for _, v := range []string{c.Executable, c.StateDir} {
		if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "\"\n\r\x00%$`\\") {
			return fmt.Errorf("unsupported path %q (absolute path required; quotes, newlines, %%, $ and backslashes are not allowed)", v)
		}
	}
	return nil
}

// ErrNotSupported is returned on platforms without service support.
var ErrNotSupported = errors.New("service management is not supported on this platform")

// SystemdUnit renders the systemd unit. The agent gets only CAP_NET_RAW (raw ARP/ICMP) and
// a read-only view of the system except its state directory.
func SystemdUnit(c Config) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`[Unit]
Description=%s
Documentation=https://github.com/MohamedOssama24/Smart-Home-Security
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=%s
Group=%s
ExecStart="%s" run --state-dir "%s"
Restart=on-failure
RestartSec=10
# exit codes %d (revoked from the dashboard) and %d (not enrolled): do not restart
RestartPreventExitStatus=%d %d
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths="%s"
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
`, DisplayName, ServiceUser, ServiceUser, c.Executable, c.StateDir, ExitRevoked, ExitNotEnrolled, ExitRevoked, ExitNotEnrolled, c.StateDir), nil
}

// LaunchdPlist renders the launchd daemon definition.
func LaunchdPlist(c Config) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>run</string>
        <string>--state-dir</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <!-- kept alive only while the identity exists: after a revocation it is retired -->
        <key>PathState</key>
        <dict>
            <key>%s/agent.json</key>
            <true/>
        </dict>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>Umask</key>
    <integer>63</integer>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/shsc-agent.log</string>
</dict>
</plist>
`, LaunchdLabel, xmlEscape(c.Executable), xmlEscape(c.StateDir), xmlEscape(c.StateDir)), nil
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
