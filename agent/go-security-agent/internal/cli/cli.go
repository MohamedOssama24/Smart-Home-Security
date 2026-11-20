// Package cli implements the agent command-line interface. Commands are added milestone by
// milestone; only implemented commands are listed.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"shsc/agent/internal/agentauth"
	"shsc/agent/internal/buildinfo"
	"shsc/agent/internal/cloud"
	"shsc/agent/internal/identity"
	"shsc/agent/internal/service"
)

// Exit codes. ExitRevoked and ExitNotEnrolled tell the service manager not to restart.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitRevoked     = service.ExitRevoked
	ExitNotEnrolled = service.ExitNotEnrolled
)

const usage = `Smart Home Security Check - local security agent

Usage:
  shsc-agent <command> [flags]

Commands:
  enroll      Register this agent for a home with a one-time enrollment token
  run         Run the agent: heartbeat, self-diagnosis and event queue (used by the service)
  service     Manage the system service: install | uninstall | start | stop | status
  diagnose    Show capabilities, network interfaces, local queue and backend connectivity
  status      Authenticate with the backend and show the agent/home binding
  rotate-key  Replace the agent key (the old key stops working immediately)
  router      Configure the read-only router integrations (TR-064, SNMP) with your credentials
  homeassistant  Configure the read-only Home Assistant integration with your long-lived token
  directory      Configure the read-only Active Directory logons integration (who uses which IP)
  sophos         Configure the passive Sophos Firewall syslog integration (who uses which IP)
  version     Print version information (use --json for machine-readable output)
  help        Show this help

The enrollment token can be passed with --token-file or the SHSC_ENROLLMENT_TOKEN
environment variable (preferred over --token, which is visible in the process list).
The agent never starts a scan by itself: scans are started by the owner from the dashboard.
`

const requestTimeout = 60 * time.Second

// Run executes the command described by args (without the program name) and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}

	switch args[0] {
	case "enroll":
		return runEnroll(args[1:], stdout, stderr)
	case "run":
		return runAgent(args[1:], stdout, stderr)
	case "service":
		return runService(args[1:], stdout, stderr)
	case "diagnose":
		return runDiagnose(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "rotate-key":
		return runRotate(args[1:], stdout, stderr)
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "router":
		return runRouter(args[1:], stdout, stderr)
	case "directory":
		return runDirectory(args[1:], stdout, stderr)
	case "sophos":
		return runSophos(args[1:], stdout, stderr)
	case "homeassistant":
		return runHomeAssistant(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return ExitUsage
	}
}

func stateDirFlag(fs *flag.FlagSet) *string {
	return fs.String("state-dir", identity.DefaultDir(), "directory holding the agent identity")
}

func parse(fs *flag.FlagSet, args []string, stderr io.Writer) bool {
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return false
	}
	return true
}

func runEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	api := fs.String("api", "", "backend base URL, https only (e.g. https://security.example.com)")
	token := fs.String("token", "", "one-time enrollment token (prefer --token-file or SHSC_ENROLLMENT_TOKEN)")
	tokenFile := fs.String("token-file", "", "file containing the enrollment token")
	caFile := fs.String("ca-file", "", "extra CA certificate (PEM) to trust, e.g. a development certificate")
	name := fs.String("name", "", "display name of this agent (default: hostname)")
	stateDir := stateDirFlag(fs)
	if !parse(fs, args, stderr) {
		return ExitUsage
	}
	if *api == "" {
		fmt.Fprintln(stderr, "enroll: --api is required")
		return ExitUsage
	}
	secret, err := enrollmentToken(*token, *tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "enroll: %v\n", err)
		return ExitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	service := agentauth.Service{Store: identity.Store{Dir: *stateDir}}
	state, err := service.Enroll(ctx, *api, *caFile, secret, *name)
	if err != nil {
		return fail(stderr, "enroll", err)
	}
	fmt.Fprintf(stdout, "Agent enrolled.\n  agent id: %s\n  home id:  %s\n  identity: %s\n",
		state.AgentID, state.HomeID, *stateDir)
	return ExitOK
}

func enrollmentToken(flagValue, file string) (string, error) {
	switch {
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	case flagValue != "":
		return flagValue, nil
	case os.Getenv("SHSC_ENROLLMENT_TOKEN") != "":
		return os.Getenv("SHSC_ENROLLMENT_TOKEN"), nil
	default:
		return "", errors.New("an enrollment token is required (--token-file, SHSC_ENROLLMENT_TOKEN or --token)")
	}
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print as JSON")
	stateDir := stateDirFlag(fs)
	if !parse(fs, args, stderr) {
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	info, err := agentauth.Service{Store: identity.Store{Dir: *stateDir}}.Check(ctx)
	if err != nil {
		return fail(stderr, "status", err)
	}
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			return fail(stderr, "status", err)
		}
		return ExitOK
	}
	fmt.Fprintf(stdout, "Authenticated.\n  agent id: %s\n  home:     %s (%s)\n  token valid until: %s\n",
		info.AgentID, info.HomeName, info.HomeID, info.TokenExpiresAt.Format(time.RFC3339))
	return ExitOK
}

func runRotate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	if !parse(fs, args, stderr) {
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	store := identity.Store{Dir: *stateDir}
	credential, err := agentauth.Service{Store: store}.RotateKey(ctx)
	if ownerErr := store.MatchOwner(); ownerErr != nil {
		fmt.Fprintf(stderr, "rotate-key: warning: cannot give the new key to the service user: %v\n", ownerErr)
	}
	if err != nil {
		return fail(stderr, "rotate-key", err)
	}
	fmt.Fprintf(stdout, "Key rotated. New credential: %s\n", credential)
	return ExitOK
}

// fail prints an actionable message; never prints tokens or keys.
func fail(stderr io.Writer, command string, err error) int {
	switch {
	case cloud.IsCode(err, "AGENT_REVOKED"):
		fmt.Fprintf(stderr, "%s: this agent has been revoked from the dashboard; enroll it again with a new token\n", command)
	case cloud.IsCode(err, "INVALID_ENROLLMENT_TOKEN"):
		fmt.Fprintf(stderr, "%s: the enrollment token is invalid, expired, revoked or already used; create a new one from the dashboard\n", command)
	default:
		fmt.Fprintf(stderr, "%s: %v\n", command, err)
	}
	return ExitError
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print as JSON")
	if !parse(fs, args, stderr) {
		return ExitUsage
	}

	info := buildinfo.Get()
	if *asJSON {
		enc := json.NewEncoder(stdout)
		if err := enc.Encode(info); err != nil {
			fmt.Fprintf(stderr, "version: %v\n", err)
			return ExitError
		}
		return ExitOK
	}
	fmt.Fprintln(stdout, info.String())
	return ExitOK
}
