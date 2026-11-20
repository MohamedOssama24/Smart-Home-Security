package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"shsc/agent/internal/identities"
	"shsc/agent/internal/identity"
	"shsc/agent/internal/scan"
)

const directoryUsage = `Usage: shsc-agent directory <set|show|remove> [flags]

Configures the read-only Active Directory integration (M24): during the scans started from the
dashboard the agent reads, from the Security log of YOUR domain controller, which account logged
on from which IP address (events 4624 and 4768 of the last hours) and sends only the pairs
IP ↔ account of the authorized networks. Use an account YOUR IT created for this purpose, member
of "Event Log Readers" only. The password is read from standard input, stored on this agent only
(protected like the agent key) and never printed or sent to the backend. Inform the people whose
devices are on the network: their account name is shown next to their devices.

  set    --server DC-IP --user ACCOUNT [--domain DOMAIN] [--hours 12]   stdin: password
  show   print the configured domain controller and account (without the password)
  remove delete the Active Directory settings
`

const sophosUsage = `Usage: shsc-agent sophos <set|show|remove> [flags]

Configures the passive Sophos Firewall integration (M24): YOUR firewall sends its syslog to this
agent (UDP, port 5514 by default) and the agent keeps only the pairs IP ↔ user of the
authentication events, for the last 12 hours, in memory. Packets from any other address are
dropped and the messages are never stored or logged. Restart the agent after a change.

  set    --firewall FIREWALL-IP [--listen :5514]
  show   print the configured firewall and listening address
  remove delete the Sophos settings
`

func runDirectory(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, directoryUsage)
		return ExitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet("directory "+cmd, flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	server := fs.String("server", "", "IP address of the domain controller")
	user := fs.String("user", "", "read-only account (member of Event Log Readers)")
	domain := fs.String("domain", "", "domain of the account, e.g. CORP")
	hours := fs.Int("hours", identities.DefaultHours, "how many hours of logons are read at each scan")
	if !parse(fs, args[1:], stderr) {
		return ExitUsage
	}
	store := identity.Store{Dir: *stateDir}
	switch cmd {
	case "show":
		cfg, err := scan.LoadDirectory(store)
		if err != nil {
			return fail(stderr, "directory", err)
		}
		if cfg == nil {
			fmt.Fprintln(stdout, "no Active Directory integration configured")
			return ExitOK
		}
		account := cfg.User
		if cfg.Domain != "" {
			account = cfg.Domain + `\` + cfg.User
		}
		fmt.Fprintf(stdout, "Active Directory: domain controller %s, account %s, last %s, password set\n",
			cfg.ServerIP(), account, cfg.Window())
		return ExitOK
	case "remove":
		if err := store.RemoveIntegration("directory"); err != nil {
			return fail(stderr, "directory", err)
		}
		fmt.Fprintln(stdout, "Active Directory settings removed")
		return ExitOK
	case "set":
	default:
		fmt.Fprint(stderr, directoryUsage)
		return ExitUsage
	}
	password := ""
	if s := bufio.NewScanner(stdin); s.Scan() {
		password = strings.TrimRight(s.Text(), "\r\n")
	}
	cfg := identities.DirectoryConfig{Server: strings.TrimSpace(*server), User: strings.TrimSpace(*user),
		Domain: strings.TrimSpace(*domain), Password: password, Hours: *hours}
	if err := scan.SaveDirectory(store, cfg); err != nil {
		return fail(stderr, "directory", err)
	}
	fmt.Fprintln(stdout, "Active Directory integration saved; it is used only by scans started from the dashboard")
	return ExitOK
}

func runSophos(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, sophosUsage)
		return ExitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet("sophos "+cmd, flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	firewall := fs.String("firewall", "", "IP address of the Sophos firewall")
	listen := fs.String("listen", fmt.Sprintf(":%d", identities.DefaultSyslogPort), "local UDP address for the syslog")
	if !parse(fs, args[1:], stderr) {
		return ExitUsage
	}
	store := identity.Store{Dir: *stateDir}
	switch cmd {
	case "show":
		cfg, err := scan.LoadSophos(store)
		if err != nil {
			return fail(stderr, "sophos", err)
		}
		if cfg == nil {
			fmt.Fprintln(stdout, "no Sophos integration configured")
			return ExitOK
		}
		fmt.Fprintf(stdout, "Sophos: firewall %s, syslog on UDP %s\n", cfg.FirewallIP(), cfg.ListenAddr())
		return ExitOK
	case "remove":
		if err := store.RemoveIntegration("sophos"); err != nil {
			return fail(stderr, "sophos", err)
		}
		fmt.Fprintln(stdout, "Sophos settings removed; restart the agent to stop listening")
		return ExitOK
	case "set":
	default:
		fmt.Fprint(stderr, sophosUsage)
		return ExitUsage
	}
	cfg := identities.SophosConfig{Firewall: strings.TrimSpace(*firewall), Listen: strings.TrimSpace(*listen)}
	if err := scan.SaveSophos(store, cfg); err != nil {
		return fail(stderr, "sophos", err)
	}
	fmt.Fprintf(stdout, "Sophos integration saved: send the firewall syslog to this computer, UDP %s; restart the agent\n",
		cfg.ListenAddr())
	return ExitOK
}

// sophosListener prepares the Sophos syslog listener when the integration is configured (the
// settings are read at start: "shsc-agent sophos" asks to restart the agent).
func sophosListener(store identity.Store, log *slog.Logger) (*identities.Table, func(context.Context)) {
	cfg, err := scan.LoadSophos(store)
	if err != nil {
		log.Warn("sophos integration disabled", "error", err.Error())
		return nil, nil
	}
	if cfg == nil {
		return nil, nil
	}
	table := identities.NewTable()
	return table, func(ctx context.Context) {
		if err := identities.Listen(ctx, *cfg, table, log, time.Now); err != nil {
			log.Warn("sophos syslog listener stopped", "error", err.Error())
		}
	}
}
