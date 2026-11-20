package identities

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Defaults of the Active Directory reader.
const (
	DefaultHours = 12
	MaxHours     = 72
	maxEvents    = 20000 // newest first: older events are not read
)

// DirectoryConfig is the read-only access to the Security log of one domain controller of the
// owner, with an account the owner's IT created for this purpose (member of "Event Log Readers").
type DirectoryConfig struct {
	Server   string `json:"server"` // IP address of the domain controller
	Domain   string `json:"domain,omitempty"`
	User     string `json:"user"`
	Password string `json:"password"`
	Hours    int    `json:"hours,omitempty"` // how far back the logons are read
}

// ErrUnsupported is returned where the Windows event log API does not exist.
var ErrUnsupported = errors.New("reading Active Directory logons needs the Windows agent")

// Validate checks the settings.
func (c DirectoryConfig) Validate() error {
	if _, ok := ParseIP(c.Server); !ok {
		return errors.New("--server must be the IP address of the domain controller")
	}
	if strings.TrimSpace(c.User) == "" || strings.ContainsAny(c.User, `\@`) {
		return errors.New("--user must be the account name only (the domain goes in --domain)")
	}
	if c.Password == "" {
		return errors.New("the password (standard input) is empty")
	}
	if c.Hours < 0 || c.Hours > MaxHours {
		return fmt.Errorf("--hours must be between 1 and %d", MaxHours)
	}
	return nil
}

// ServerIP is the address of the domain controller (valid after Validate).
func (c DirectoryConfig) ServerIP() netip.Addr {
	a, _ := ParseIP(c.Server)
	return a
}

// Window is how far back the logons are read.
func (c DirectoryConfig) Window() time.Duration {
	if c.Hours <= 0 {
		return DefaultHours * time.Hour
	}
	return time.Duration(c.Hours) * time.Hour
}

// logonQuery selects the successful logons (4624) and Kerberos ticket requests (4768) of the window.
func logonQuery(window time.Duration) string {
	return fmt.Sprintf("*[System[(EventID=4624 or EventID=4768) and TimeCreated[timediff(@SystemTime) <= %d]]]",
		window.Milliseconds())
}

// person logon types of event 4624: interactive, network, unlock, remote desktop, cached.
var logonTypes = map[string]bool{"2": true, "3": true, "7": true, "10": true, "11": true}

type eventXML struct {
	System struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// ParseLogon extracts the pair client IP ↔ account from one event rendered as XML. Computer
// accounts, anonymous logons and local addresses are ignored.
func ParseLogon(raw []byte) (Identity, bool) {
	var e eventXML
	if err := xml.Unmarshal(raw, &e); err != nil {
		return Identity{}, false
	}
	data := map[string]string{}
	for _, d := range e.Data {
		data[d.Name] = d.Value
	}
	switch e.System.EventID {
	case 4624:
		if !logonTypes[strings.TrimSpace(data["LogonType"])] {
			return Identity{}, false
		}
	case 4768:
		if strings.TrimSpace(data["Status"]) != "" && strings.TrimSpace(data["Status"]) != "0x0" {
			return Identity{}, false // failed ticket request
		}
	default:
		return Identity{}, false
	}
	account := NormalizeAccount(data["TargetUserName"])
	ip, ok := ParseIP(data["IpAddress"])
	if account == "" || !ok {
		return Identity{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(e.System.TimeCreated.SystemTime))
	if err != nil {
		return Identity{}, false
	}
	return Identity{IP: ip, Account: account, Source: SourceDirectory, ObservedAt: at.UTC()}, true
}

// ReadDirectory reads the logons of the window from the domain controller (Windows only).
func ReadDirectory(ctx context.Context, cfg DirectoryConfig) ([]Identity, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	table := NewTable()
	err := readEvents(ctx, cfg, logonQuery(cfg.Window()), maxEvents, func(raw []byte) {
		if id, ok := ParseLogon(raw); ok {
			table.Put(id)
		}
	})
	if err != nil {
		return nil, err
	}
	return table.Snapshot(time.Time{}, func(netip.Addr) bool { return true }), nil
}
