package identities

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// All addresses, accounts and messages are [MOCK] (192.168.63.0/24, 192.168.65.0/24).

var mockNow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func TestNormalizeAccountKeepsOnlyPeople(t *testing.T) {
	cases := map[string]string{
		`CORP\mario.rossi`:       "mario.rossi",
		"anna.bianchi@corp.test": "anna.bianchi",
		` "luca" `:               "luca",
		"PC-UFFICIO01$":          "",
		"ANONYMOUS LOGON":        "",
		"-":                      "",
		"":                       "",
		"SYSTEM":                 "",
		"bad\x01name":            "",
	}
	for in, want := range cases {
		if got := NormalizeAccount(in); got != want {
			t.Errorf("NormalizeAccount(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSophosFirewallAndUTMLines(t *testing.T) {
	sfos := `<30>device_name="SFW" timestamp="2026-11-19T11:58:00+0100" log_type="Event" ` +
		`log_component="Firewall Authentication" status="Successful" user_name="mario.rossi" ` +
		`usergroupname="Ufficio" src_ip="192.168.63.21" message="User mario.rossi logged in"`
	id, ok := ParseSophos(sfos, mockNow)
	if !ok || id.Account != "mario.rossi" || id.IP != netip.MustParseAddr("192.168.63.21") || id.Source != SourceFirewall {
		t.Fatalf("SFOS: %+v %v", id, ok)
	}
	utm := `2026:11:19-11:58:00 utm aua[123]: id="3004" severity="info" sys="System" sub="auth" ` +
		`name="Authentication successful" srcip="192.168.63.22" host="" user="CORP\anna.bianchi" caller="portal"`
	if id, ok := ParseSophos(utm, mockNow); !ok || id.Account != "anna.bianchi" || id.IP.String() != "192.168.63.22" {
		t.Fatalf("UTM: %+v %v", id, ok)
	}
	for _, line := range []string{
		`log_type="Firewall" src_ip=192.168.63.23 dst_ip=192.168.63.1`,     // no user
		`user_name="" src_ip=192.168.63.23`,                                // empty user
		`user_name="PC01$" src_ip=192.168.63.23`,                           // computer account
		`user_name="mario.rossi" src_ip=127.0.0.1`,                         // local address
		`user_name="mario.rossi" message="from src_ip=192.168.63.24 here"`, // inside a quoted value
	} {
		if id, ok := ParseSophos(line, mockNow); ok {
			t.Errorf("%q: unexpected %+v", line, id)
		}
	}
}

func logonXML(id int, user, ip, logonType, status string) []byte {
	return []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>` +
		`<EventID>` + strconv.Itoa(id) + `</EventID><TimeCreated SystemTime="2026-11-19T10:15:30.1234567Z"/></System>` +
		`<EventData><Data Name="TargetUserName">` + user + `</Data><Data Name="TargetDomainName">CORP</Data>` +
		`<Data Name="LogonType">` + logonType + `</Data><Data Name="Status">` + status + `</Data>` +
		`<Data Name="IpAddress">` + ip + `</Data></EventData></Event>`)
}

func TestParseLogonEvents(t *testing.T) {
	id, ok := ParseLogon(logonXML(4624, "mario.rossi", "::ffff:192.168.63.21", "3", ""))
	if !ok || id.Account != "mario.rossi" || id.IP.String() != "192.168.63.21" || id.Source != SourceDirectory ||
		!id.ObservedAt.Equal(time.Date(2026, 11, 19, 10, 15, 30, 123456700, time.UTC)) {
		t.Fatalf("4624: %+v %v", id, ok)
	}
	if id, ok := ParseLogon(logonXML(4768, "anna.bianchi", "::ffff:192.168.63.22", "", "0x0")); !ok || id.Account != "anna.bianchi" {
		t.Fatalf("4768: %+v %v", id, ok)
	}
	for name, raw := range map[string][]byte{
		"computer account": logonXML(4624, "PC-UFFICIO01$", "192.168.63.30", "3", ""),
		"service logon":    logonXML(4624, "mario.rossi", "192.168.63.21", "5", ""),
		"failed ticket":    logonXML(4768, "mario.rossi", "192.168.63.21", "", "0x18"),
		"local logon":      logonXML(4624, "mario.rossi", "-", "2", ""),
		"other event":      logonXML(4625, "mario.rossi", "192.168.63.21", "3", ""),
		"not xml":          []byte("<Event"),
	} {
		if id, ok := ParseLogon(raw); ok {
			t.Errorf("%s: unexpected %+v", name, id)
		}
	}
}

func TestTableKeepsTheLatestAndForgetsOldEntries(t *testing.T) {
	ip := netip.MustParseAddr("192.168.63.21")
	table := NewTable()
	table.Put(Identity{IP: ip, Account: "mario.rossi", ObservedAt: mockNow})
	table.Put(Identity{IP: ip, Account: "vecchio", ObservedAt: mockNow.Add(-time.Hour)})
	table.Put(Identity{IP: netip.MustParseAddr("192.168.65.9"), Account: "fuori", ObservedAt: mockNow})
	table.Put(Identity{IP: netip.MustParseAddr("192.168.63.40"), Account: "scaduto", ObservedAt: mockNow.Add(-48 * time.Hour)})
	lan := netip.MustParsePrefix("192.168.63.0/24")
	got := table.Snapshot(mockNow.Add(-12*time.Hour), lan.Contains)
	if len(got) != 1 || got[0].Account != "mario.rossi" {
		t.Fatalf("snapshot: %+v", got)
	}
	for i := range MaxEntries + 10 {
		table.Put(Identity{IP: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), Account: "x",
			ObservedAt: mockNow.Add(time.Duration(i) * time.Second)})
	}
	if n := len(table.Snapshot(time.Time{}, func(netip.Addr) bool { return true })); n != MaxEntries {
		t.Fatalf("table size %d", n)
	}
}

func TestReceiveAcceptsOnlyTheFirewall(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	table := NewTable()
	done := make(chan error, 1)
	// the sender is 127.0.0.1: first accepted as the firewall, then refused as a stranger
	go func() {
		done <- Receive(ctx, conn, netip.MustParseAddr("127.0.0.1"), table, slog.New(slog.DiscardHandler),
			func() time.Time { return mockNow })
	}()
	send := func(msg string) {
		c, err := net.Dial("udp", conn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte(msg))
	}
	send(`user_name="mario.rossi" src_ip=192.168.63.21` + "\n" + `user_name="anna.bianchi" src_ip=192.168.63.22`)
	all := func(netip.Addr) bool { return true }
	deadline := time.Now().Add(5 * time.Second)
	for len(table.Snapshot(time.Time{}, all)) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := table.Snapshot(time.Time{}, all); len(got) != 2 {
		t.Fatalf("accepted: %+v", got)
	}
	cancel()
	_ = conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	stranger, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	other := NewTable()
	go func() {
		done <- Receive(ctx2, stranger, netip.MustParseAddr("192.168.63.1"), other, slog.New(slog.DiscardHandler),
			func() time.Time { return mockNow })
	}()
	conn = stranger
	send(`user_name="intruso" src_ip=192.168.63.50`)
	time.Sleep(200 * time.Millisecond)
	cancel2()
	_ = stranger.Close()
	<-done
	if got := other.Snapshot(time.Time{}, all); len(got) != 0 {
		t.Fatalf("stranger accepted: %+v", got)
	}
}

func TestDirectoryConfigValidation(t *testing.T) {
	ok := DirectoryConfig{Server: "192.168.63.2", User: "shsc-reader", Password: "MOCK-password"}
	if err := ok.Validate(); err != nil || ok.Window() != DefaultHours*time.Hour {
		t.Fatalf("valid config: %v %v", err, ok.Window())
	}
	for name, c := range map[string]DirectoryConfig{
		"host name":      {Server: "dc01.corp.test", User: "u", Password: "p"},
		"domain\\user":   {Server: "192.168.63.2", User: `CORP\u`, Password: "p"},
		"no password":    {Server: "192.168.63.2", User: "u"},
		"too many hours": {Server: "192.168.63.2", User: "u", Password: "p", Hours: 100},
	} {
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if q := logonQuery(2 * time.Hour); q != "*[System[(EventID=4624 or EventID=4768) and TimeCreated[timediff(@SystemTime) <= 7200000]]]" {
		t.Fatalf("query %s", q)
	}
}
