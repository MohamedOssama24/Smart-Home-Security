// Package identities collects which account is using which IP address of the home (M24, ADR-083):
// the logons recorded by the owner's Active Directory domain controller and the authentications
// of the owner's Sophos firewall. Only the pair IP ↔ account (and when it was seen) is kept:
// everything else in the events and syslog messages is discarded and never logged.
package identities

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Sources of an identity.
const (
	SourceDirectory = "DIRECTORY" // Active Directory logon events
	SourceFirewall  = "FIREWALL"  // Sophos firewall authentications
)

// MaxEntries bounds the identities kept in memory and uploaded per scan.
const MaxEntries = 4096

// Identity is the account last seen on an IP address.
type Identity struct {
	IP         netip.Addr
	Account    string
	Source     string
	ObservedAt time.Time
}

// NormalizeAccount returns the bare account name ("DOMAIN\mario.rossi" and
// "mario.rossi@corp.local" become "mario.rossi") or "" when it does not identify a person:
// computer accounts ("PC01$"), anonymous and system logons, empty values.
func NormalizeAccount(raw string) string {
	a := strings.Trim(strings.TrimSpace(raw), `"`)
	if i := strings.LastIndex(a, `\`); i >= 0 {
		a = a[i+1:]
	}
	if i := strings.Index(a, "@"); i >= 0 {
		a = a[:i]
	}
	a = strings.TrimSpace(a)
	if a == "" || len(a) > 100 || strings.HasSuffix(a, "$") {
		return ""
	}
	switch strings.ToLower(a) {
	case "-", "n/a", "na", "unknown", "anonymous", "anonymous logon", "system", "local service",
		"network service", "guest", "krbtgt", "dwm-1", "umfd-0", "umfd-1":
		return ""
	}
	for _, r := range a {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return a
}

// ParseIP accepts the address formats of Windows events and syslog ("::ffff:192.168.1.5",
// "192.168.1.5"); loopback, unspecified and link-local addresses are rejected.
func ParseIP(raw string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(raw, `"[]`)))
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}

// Table keeps the latest identity of each IP address; it is safe for concurrent use.
type Table struct {
	mu      sync.Mutex
	entries map[netip.Addr]Identity
}

// NewTable returns an empty table.
func NewTable() *Table { return &Table{entries: map[netip.Addr]Identity{}} }

// Put records an identity when it is newer than the one already known for its IP. When the
// table is full the oldest entry makes room.
func (t *Table) Put(id Identity) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.entries[id.IP]; ok {
		if !id.ObservedAt.After(old.ObservedAt) {
			return
		}
	} else if len(t.entries) >= MaxEntries {
		var oldest netip.Addr
		var at time.Time
		for ip, e := range t.entries {
			if !oldest.IsValid() || e.ObservedAt.Before(at) {
				oldest, at = ip, e.ObservedAt
			}
		}
		delete(t.entries, oldest)
	}
	t.entries[id.IP] = id
}

// Snapshot returns the identities seen after since whose IP satisfies inScope.
func (t *Table) Snapshot(since time.Time, inScope func(netip.Addr) bool) []Identity {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Identity, 0, len(t.entries))
	for ip, e := range t.entries {
		if e.ObservedAt.Before(since) {
			delete(t.entries, ip) // too old: forgotten
			continue
		}
		if inScope(ip) {
			out = append(out, e)
		}
	}
	return out
}

// Merge returns, for each IP, the most recent identity among the given lists (at most MaxEntries).
func Merge(lists ...[]Identity) []Identity {
	t := NewTable()
	for _, l := range lists {
		for _, id := range l {
			t.Put(id)
		}
	}
	return t.Snapshot(time.Time{}, func(netip.Addr) bool { return true })
}
