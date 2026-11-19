package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"shsc/agent/internal/capabilities"
	"shsc/agent/internal/discovery"
	"shsc/agent/internal/identity"
	"shsc/agent/internal/scan"
)

const routerUsage = `Usage: shsc-agent router <set-tr064|set-snmp|show|remove> [flags]

Configures the read-only router integrations used by the network discovery to read the host
table of YOUR router, with credentials YOU created on it. They are stored on this agent only
(protected like the agent key) and never sent to the backend. Secrets are read from standard
input, one per line, and never printed. Default credentials (e.g. SNMP "public") are refused.

  set-tr064 --address IP [--username USER] [--port 49000]     stdin: router password
  set-snmp  --address IP --version 2c                         stdin: community
  set-snmp  --address IP --version 3 --username USER [--auth SHA256] [--priv AES]
                                                              stdin: auth password, privacy password
  show      print the configured integrations (without secrets)
  remove    delete the router settings
`

// stdin is replaced in tests.
var stdin io.Reader = os.Stdin

func runRouter(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, routerUsage)
		return ExitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet("router "+cmd, flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	address := fs.String("address", "", "IP address of the router (must belong to an authorized network)")
	username := fs.String("username", "", "user name")
	port := fs.Int("port", 0, "port (TR-064 default 49000, SNMP default 161)")
	version := fs.String("version", "", `SNMP version: "2c" or "3"`)
	auth := fs.String("auth", "", "SNMPv3 authentication protocol: SHA, SHA224, SHA256, SHA384, SHA512, MD5")
	priv := fs.String("priv", "", "SNMPv3 privacy protocol: AES, AES192, AES256, DES")
	if !parse(fs, args[1:], stderr) {
		return ExitUsage
	}
	store := identity.Store{Dir: *stateDir}
	cfg, err := scan.LoadRouter(store)
	if err != nil {
		fmt.Fprintf(stderr, "router: stored settings ignored: %v\n", err)
		cfg = nil
	}
	switch cmd {
	case "show":
		if cfg == nil {
			fmt.Fprintln(stdout, "no router integration configured")
			return ExitOK
		}
		fmt.Fprintf(stdout, "router address: %s\n", cfg.Address)
		if t := cfg.TR064; t != nil {
			fmt.Fprintf(stdout, "TR-064: user %q, port %d, password set\n", t.Username, defaultPort(t.Port, 49000))
		}
		if s := cfg.SNMP; s != nil {
			if s.Version == "2c" {
				fmt.Fprintf(stdout, "SNMP v2c: port %d, community set\n", defaultPort(s.Port, 161))
			} else {
				fmt.Fprintf(stdout, "SNMP v3: user %q, auth %s, priv %s, port %d\n", s.Username,
					orNone(s.AuthProtocol), orNone(s.PrivProtocol), defaultPort(s.Port, 161))
			}
		}
		return ExitOK
	case "remove":
		if err := store.RemoveRouter(); err != nil {
			return fail(stderr, "router", err)
		}
		fmt.Fprintln(stdout, "router settings removed")
		return ExitOK
	case "set-tr064", "set-snmp":
	default:
		fmt.Fprint(stderr, routerUsage)
		return ExitUsage
	}

	next := discovery.RouterConfig{Address: strings.TrimSpace(*address)}
	if cfg != nil && cfg.Address == next.Address {
		next = *cfg // keep the other integration of the same router
	}
	secrets := bufio.NewScanner(stdin)
	readSecret := func() string {
		if secrets.Scan() {
			return strings.TrimRight(secrets.Text(), "\r")
		}
		return ""
	}
	if cmd == "set-tr064" {
		next.TR064 = &discovery.TR064Config{Username: *username, Port: *port, Password: readSecret()}
	} else {
		s := &discovery.SNMPConfig{Version: *version, Port: *port}
		if *version == "2c" {
			s.Community = readSecret()
		} else {
			s.Username, s.AuthProtocol, s.PrivProtocol = *username, strings.ToUpper(*auth), strings.ToUpper(*priv)
			if s.AuthProtocol != "" {
				s.AuthPassword = readSecret()
			}
			if s.PrivProtocol != "" {
				s.PrivPassword = readSecret()
			}
		}
		next.SNMP = s
	}
	if err := scan.SaveRouter(store, next); err != nil {
		return fail(stderr, "router", err)
	}
	fmt.Fprintf(stdout, "router integration saved (%s); it is used only by scans started from the dashboard\n",
		strings.Join(next.Integrations(), ", "))
	return ExitOK
}

// detectWithRouter is the self-diagnosis plus the configured router integrations.
func detectWithRouter(store identity.Store) capabilities.Report {
	r := capabilities.Detect()
	if cfg, err := scan.LoadRouter(store); err == nil && cfg != nil {
		r.RouterIntegrations = cfg.Integrations()
	}
	return r
}

func defaultPort(p, def int) int {
	if p == 0 {
		return def
	}
	return p
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
