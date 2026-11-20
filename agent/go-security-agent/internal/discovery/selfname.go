package discovery

import (
	"os"
	"strings"
)

// hostName is the agent host's own name source (replaced in tests).
var hostName = os.Hostname

// selfName is the name of the agent host as the operating system knows it: it names the SELF
// observation, which no network technique can (a host does not answer its own broadcasts).
// Only the first label, at most 63 characters of letters, digits, '-' and '_'; otherwise empty.
func selfName() string {
	name, err := hostName()
	if err != nil {
		return ""
	}
	name, _, _ = strings.Cut(strings.TrimSpace(name), ".")
	if name == "" || len(name) > 63 {
		return ""
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return ""
		}
	}
	return name
}
