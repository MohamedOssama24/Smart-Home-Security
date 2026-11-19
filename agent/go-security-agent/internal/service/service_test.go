package service

import (
	"strings"
	"testing"
)

func TestSystemdUnitGrantsOnlyNetRawAndDoesNotRestartARevokedAgent(t *testing.T) {
	unit, err := SystemdUnit(Config{Executable: "/usr/local/bin/shsc-agent", StateDir: "/var/lib/shsc-agent"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ExecStart="/usr/local/bin/shsc-agent" run --state-dir "/var/lib/shsc-agent"`,
		"User=shsc",
		"AmbientCapabilities=CAP_NET_RAW",
		"CapabilityBoundingSet=CAP_NET_RAW",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		`ReadWritePaths="/var/lib/shsc-agent"`,
		"Restart=on-failure",
		"RestartPreventExitStatus=3 4",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit misses %q", want)
		}
	}
	if strings.Contains(unit, "CAP_SYS_ADMIN") || strings.Contains(unit, "User=root") {
		t.Error("the unit must not grant more privileges")
	}
}

func TestLaunchdPlistKeepsAliveOnlyWhileEnrolled(t *testing.T) {
	plist, err := LaunchdPlist(Config{Executable: "/usr/local/bin/shsc-agent",
		StateDir: "/Library/Application Support/SHSC/agent"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>com.shsc.agent</string>",
		"<string>/usr/local/bin/shsc-agent</string>",
		"<string>run</string>",
		"<string>/Library/Application Support/SHSC/agent</string>",
		"<key>PathState</key>",
		"<key>/Library/Application Support/SHSC/agent/agent.json</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist misses %q", want)
		}
	}
}

func TestUnsafePathsAreRejected(t *testing.T) {
	for _, bad := range []Config{
		{Executable: "shsc-agent", StateDir: "/var/lib/shsc-agent"},
		{Executable: "/usr/local/bin/shsc-agent", StateDir: "/var/lib/a\"; rm -rf /"},
		{Executable: "/usr/local/bin/shsc-agent", StateDir: "/var/lib/$HOME"},
		{Executable: "/usr/local/bin/shsc-agent\nExecStartPre=/bin/sh", StateDir: "/var/lib/shsc-agent"},
		{Executable: "/usr/local/bin/shsc-agent", StateDir: "/var/lib/100%"},
	} {
		if _, err := SystemdUnit(bad); err == nil {
			t.Errorf("unit accepted %+v", bad)
		}
		if _, err := LaunchdPlist(bad); err == nil {
			t.Errorf("plist accepted %+v", bad)
		}
	}
}

func TestXMLEscape(t *testing.T) {
	if got := xmlEscape("/opt/a&b<c>"); got != "/opt/a&amp;b&lt;c&gt;" {
		t.Fatal(got)
	}
}
