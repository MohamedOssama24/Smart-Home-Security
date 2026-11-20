package identities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"
)

// DefaultSyslogPort is the UDP port the agent listens on for the Sophos syslog (not 514, which
// would need administrator rights on some systems and is often taken).
const DefaultSyslogPort = 5514

const maxSyslogMessage = 8192

// SophosConfig is the passive Sophos integration: the agent receives the syslog the firewall
// sends to it and accepts only packets coming from the firewall address.
type SophosConfig struct {
	Firewall string `json:"firewall"` // IP address of the Sophos firewall
	Listen   string `json:"listen"`   // local UDP address, e.g. ":5514"
}

// Validate checks the settings.
func (c SophosConfig) Validate() error {
	if _, ok := ParseIP(c.Firewall); !ok {
		return errors.New("--firewall must be the IP address of the Sophos firewall")
	}
	if _, err := net.ResolveUDPAddr("udp", c.ListenAddr()); err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	return nil
}

// FirewallIP is the address of the firewall (valid after Validate).
func (c SophosConfig) FirewallIP() netip.Addr {
	a, _ := ParseIP(c.Firewall)
	return a
}

// ListenAddr is the local UDP address, ":5514" by default.
func (c SophosConfig) ListenAddr() string {
	if strings.TrimSpace(c.Listen) == "" {
		return fmt.Sprintf(":%d", DefaultSyslogPort)
	}
	return strings.TrimSpace(c.Listen)
}

// userKeys and ipKeys are the fields of Sophos Firewall (SFOS) and Sophos UTM log lines that
// carry the authenticated user and the client address.
var (
	userKeys = []string{"user_name", "username", "user"}
	ipKeys   = []string{"src_ip", "srcip", "client_ip"}
)

// ParseSophos extracts the pair client IP ↔ user from one syslog message (key=value fields,
// values optionally in double quotes). ok is false when the message has no such pair.
func ParseSophos(message string, at time.Time) (Identity, bool) {
	fields := keyValues(message)
	account := ""
	for _, k := range userKeys {
		if account = NormalizeAccount(fields[k]); account != "" {
			break
		}
	}
	if account == "" {
		return Identity{}, false
	}
	for _, k := range ipKeys {
		if ip, ok := ParseIP(fields[k]); ok {
			return Identity{IP: ip, Account: account, Source: SourceFirewall, ObservedAt: at}, true
		}
	}
	return Identity{}, false
}

// keyValues parses `a=1 b="two words" c=3`; only the keys we need are kept.
func keyValues(s string) map[string]string {
	wanted := map[string]bool{}
	for _, k := range append(append([]string{}, userKeys...), ipKeys...) {
		wanted[k] = true
	}
	out := map[string]string{}
	for i := 0; i < len(s); {
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		keyStart := strings.LastIndexAny(s[i:i+eq], " \t>:") + 1
		key := strings.ToLower(s[i+keyStart : i+eq])
		j := i + eq + 1
		var value string
		if j < len(s) && s[j] == '"' {
			end := strings.IndexByte(s[j+1:], '"')
			if end < 0 {
				value, j = s[j+1:], len(s)
			} else {
				value, j = s[j+1:j+1+end], j+end+2
			}
		} else {
			end := strings.IndexAny(s[j:], " \t")
			if end < 0 {
				value, j = s[j:], len(s)
			} else {
				value, j = s[j:j+end], j+end
			}
		}
		if wanted[key] {
			if _, seen := out[key]; !seen {
				out[key] = value
			}
		}
		i = j
	}
	return out
}

// Listen receives the syslog of the firewall until ctx ends and records the identities in table.
// Packets from any other address are dropped; message contents are never logged.
func Listen(ctx context.Context, cfg SophosConfig, table *Table, log *slog.Logger, now func() time.Time) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	conn, err := net.ListenPacket("udp", cfg.ListenAddr())
	if err != nil {
		return fmt.Errorf("sophos syslog: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	log.Info("sophos syslog listener started", "listen", conn.LocalAddr().String(), "firewall", cfg.FirewallIP().String())
	return Receive(ctx, conn, cfg.FirewallIP(), table, log, now)
}

// Receive reads packets from conn (separated from Listen for the tests).
func Receive(ctx context.Context, conn net.PacketConn, firewall netip.Addr, table *Table, log *slog.Logger,
	now func() time.Time) error {
	buf := make([]byte, maxSyslogMessage)
	dropped := 0
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("sophos syslog: %w", err)
		}
		src, ok := from.(*net.UDPAddr)
		if !ok || src.AddrPort().Addr().Unmap() != firewall {
			dropped++
			if dropped == 1 || dropped%1000 == 0 {
				log.Warn("syslog packets from an address that is not the configured firewall were dropped", "count", dropped)
			}
			continue
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if id, ok := ParseSophos(line, now()); ok {
				table.Put(id)
			}
		}
	}
}
