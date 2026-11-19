package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"

	"shsc/agent/internal/homeassistant"
	"shsc/agent/internal/identity"
	"shsc/agent/internal/scan"
)

const homeAssistantUsage = `Usage: shsc-agent homeassistant <set|show|remove> [flags]

Configures the read-only Home Assistant integration: during the scans started from the dashboard
the agent reads the device inventory of YOUR Home Assistant (also Zigbee, Z-Wave, Matter, Thread
and Bluetooth devices) with a long-lived access token YOU created in your Home Assistant profile.
URL and token are stored on this agent only (protected like the agent key) and never sent to the
backend. The token is read from standard input and never printed. Home Assistant must be on an
authorized network of the home.

  set    --url http(s)://IP[:8123] [--tls-server-name NAME]    stdin: long-lived access token
  show   print the configured URL (without the token)
  remove delete the Home Assistant settings
`

func runHomeAssistant(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, homeAssistantUsage)
		return ExitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet("homeassistant "+cmd, flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	rawURL := fs.String("url", "", "URL of Home Assistant with its IP address, e.g. http://192.168.1.10:8123")
	serverName := fs.String("tls-server-name", "", "HTTPS only: name in the certificate when it does not contain the IP")
	if !parse(fs, args[1:], stderr) {
		return ExitUsage
	}
	store := identity.Store{Dir: *stateDir}
	switch cmd {
	case "show":
		cfg, err := scan.LoadHomeAssistant(store)
		if err != nil {
			return fail(stderr, "homeassistant", err)
		}
		if cfg == nil {
			fmt.Fprintln(stdout, "no Home Assistant integration configured")
			return ExitOK
		}
		fmt.Fprintf(stdout, "Home Assistant: %s, token set\n", strings.TrimSpace(cfg.URL))
		if !cfg.HTTPS() {
			fmt.Fprintln(stdout, "warning: plain HTTP, the token travels unencrypted on the local network")
		}
		return ExitOK
	case "remove":
		if err := store.RemoveHomeAssistant(); err != nil {
			return fail(stderr, "homeassistant", err)
		}
		fmt.Fprintln(stdout, "Home Assistant settings removed")
		return ExitOK
	case "set":
	default:
		fmt.Fprint(stderr, homeAssistantUsage)
		return ExitUsage
	}
	token := ""
	if s := bufio.NewScanner(stdin); s.Scan() {
		token = strings.TrimSpace(s.Text())
	}
	cfg := homeassistant.Config{URL: strings.TrimSpace(*rawURL), Token: token, TLSServerName: *serverName}
	if err := scan.SaveHomeAssistant(store, cfg); err != nil {
		return fail(stderr, "homeassistant", err)
	}
	fmt.Fprintln(stdout, "Home Assistant integration saved; it is used only by scans started from the dashboard")
	if !cfg.HTTPS() {
		fmt.Fprintln(stdout, "warning: plain HTTP, the token travels unencrypted on the local network")
	}
	return ExitOK
}
