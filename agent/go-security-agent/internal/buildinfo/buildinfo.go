// Package buildinfo exposes the agent version metadata injected at build time with
// -ldflags "-X shsc/agent/internal/buildinfo.version=... -X ...commit=... -X ...date=...".
package buildinfo

import (
	"fmt"
	"runtime"
)

// Overridden by the linker for release builds; the defaults identify a local development build.
var (
	version = "0.0.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

// Info describes the running agent binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the build information of the current binary.
func Get() Info {
	return Info{
		Version:   version,
		Commit:    commit,
		BuildDate: date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String renders a single human-readable line.
func (i Info) String() string {
	return fmt.Sprintf("shsc-agent %s (commit %s, built %s, %s, %s/%s)",
		i.Version, i.Commit, i.BuildDate, i.GoVersion, i.OS, i.Arch)
}
