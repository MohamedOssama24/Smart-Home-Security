package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"shsc/agent/internal/agentauth"
	"shsc/agent/internal/buildinfo"
	"shsc/agent/internal/capabilities"
	"shsc/agent/internal/identity"
	"shsc/agent/internal/logging"
	"shsc/agent/internal/queue"
	"shsc/agent/internal/runner"
	"shsc/agent/internal/scan"
	"shsc/agent/internal/service"
)

const queueFile = "queue.db"

// runAgent is the long-running process started by the service manager (or by hand).
func runAgent(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	logFile := fs.String("log-file", "", "write the log to this file instead of stderr (Windows service default: <state-dir>\\agent.log)")
	if !parse(fs, args, stderr) {
		return ExitUsage
	}
	asService, err := service.IsWindowsService()
	if err != nil {
		return fail(stderr, "run", err)
	}
	if asService && *logFile == "" {
		*logFile = filepath.Join(*stateDir, "agent.log")
	}
	logger := logging.Stderr()
	if *logFile != "" {
		fileLogger, closer, err := logging.File(*logFile)
		if err != nil {
			return fail(stderr, "run", err)
		}
		defer closer.Close()
		logger = fileLogger
	}

	store := identity.Store{Dir: *stateDir}
	var work func(context.Context) error
	revoked := false
	if !store.Exists() {
		logger.Error("agent not enrolled: run 'shsc-agent enroll' first", "stateDir", *stateDir)
		if !asService {
			fmt.Fprintf(stderr, "run: %v\n", identity.ErrNotEnrolled)
			return ExitNotEnrolled
		}
		// under the Service Control Manager: stop cleanly so that it is not restarted in a loop
		work = func(context.Context) error { return nil }
	} else {
		q, err := queue.Open(filepath.Join(*stateDir, queueFile), queue.DefaultMaxBytes)
		if err != nil {
			return fail(stderr, "run", err)
		}
		defer q.Close()
		auth := agentauth.Service{Store: store}
		// the scan worker executes only signed jobs created by a user action in the dashboard
		// M24: the Sophos syslog listener fills the firewall table used by the scans
		firewall, listen := sophosListener(store, logger)
		worker := scan.New(scan.Options{Auth: auth, Queue: q, Logger: logger, Firewall: firewall})
		background := func(ctx context.Context) {
			if listen != nil {
				go listen(ctx)
			}
			worker.Run(ctx)
		}
		r := runner.New(runner.Options{Auth: auth, Queue: q, Logger: logger, Background: background,
			Detect: func() capabilities.Report { return detectWithRouter(store) }})
		work = func(ctx context.Context) error {
			err := r.Run(ctx)
			if errors.Is(err, runner.ErrRevoked) {
				revoked = true
				return nil
			}
			return err
		}
	}

	if asService {
		err = service.RunWindowsService(work)
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = work(ctx)
	}
	if revoked {
		fmt.Fprintf(stderr, "run: %v\n", runner.ErrRevoked)
		return ExitRevoked
	}
	if err != nil {
		logger.Error("agent stopped with an error", "error", err.Error())
		return fail(stderr, "run", err)
	}
	return ExitOK
}

const serviceUsage = `Usage: shsc-agent service <install|uninstall|start|stop|status> [--state-dir DIR]

install    register the system service for this binary and start it (enroll first)
uninstall  stop and remove the service (the identity is kept)
start      start the service
stop       stop the service
status     show the service state
`

func runService(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, serviceUsage)
		return ExitUsage
	}
	action := args[0]
	fs := flag.NewFlagSet("service "+action, flag.ContinueOnError)
	stateDir := stateDirFlag(fs)
	if !parse(fs, args[1:], stderr) {
		return ExitUsage
	}
	cmd := "service " + action
	var err error
	switch action {
	case "install":
		store := identity.Store{Dir: *stateDir}
		if !store.Exists() {
			fmt.Fprintf(stderr, "%s: enroll the agent first (shsc-agent enroll --state-dir %s ...)\n", cmd, *stateDir)
			return ExitNotEnrolled
		}
		exe, exeErr := os.Executable()
		if exeErr == nil {
			exe, exeErr = filepath.EvalSymlinks(exe)
		}
		if exeErr != nil {
			return fail(stderr, cmd, exeErr)
		}
		dir, dirErr := filepath.Abs(*stateDir)
		if dirErr != nil {
			return fail(stderr, cmd, dirErr)
		}
		if err := store.Secure(); err != nil {
			return fail(stderr, cmd, fmt.Errorf("protect the state directory: %w", err))
		}
		err = service.Install(service.Config{Executable: exe, StateDir: dir}, stdout)
	case "uninstall":
		err = service.Uninstall(service.Config{StateDir: *stateDir}, stdout)
	case "start":
		err = service.Start()
	case "stop":
		err = service.Stop()
	case "status":
		var state string
		state, err = service.Status()
		if err == nil {
			fmt.Fprintf(stdout, "%s: %s\n", service.Name, state)
		}
	default:
		fmt.Fprintf(stderr, "unknown service action %q\n\n%s", action, serviceUsage)
		return ExitUsage
	}
	if err != nil {
		return fail(stderr, cmd, err)
	}
	return ExitOK
}

type diagnosis struct {
	Agent        buildinfo.Info           `json:"agent"`
	StateDir     string                   `json:"stateDir"`
	Enrolled     bool                     `json:"enrolled"`
	AgentID      string                   `json:"agentId,omitempty"`
	HomeID       string                   `json:"homeId,omitempty"`
	APIURL       string                   `json:"apiUrl,omitempty"`
	Service      string                   `json:"service"`
	Capabilities capabilities.Report      `json:"capabilities"`
	Interfaces   []capabilities.Interface `json:"interfaces"`
	Queue        *queueStats              `json:"queue,omitempty"`
	Backend      *backendCheck            `json:"backend,omitempty"`
}

type queueStats struct {
	Messages int   `json:"messages"`
	Bytes    int64 `json:"bytes"`
}

type backendCheck struct {
	Reachable bool   `json:"reachable"`
	HomeName  string `json:"homeName,omitempty"`
	Error     string `json:"error,omitempty"`
}

// runDiagnose is the self-diagnosis: it never scans, it only inspects the local system and,
// unless --offline, authenticates once with the backend.
func runDiagnose(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print as JSON")
	offline := fs.Bool("offline", false, "do not contact the backend")
	stateDir := stateDirFlag(fs)
	if !parse(fs, args, stderr) {
		return ExitUsage
	}
	store := identity.Store{Dir: *stateDir}
	d := diagnosis{Agent: buildinfo.Get(), StateDir: *stateDir, Capabilities: detectWithRouter(store)}
	if state, err := service.Status(); err == nil {
		d.Service = state
	} else {
		d.Service = "unknown: " + err.Error()
	}
	ifaces, err := capabilities.Interfaces()
	if err != nil {
		fmt.Fprintf(stderr, "diagnose: cannot list interfaces: %v\n", err)
	}
	d.Interfaces = ifaces
	if len(ifaces) == 0 {
		d.Capabilities.Warnings = append(d.Capabilities.Warnings, capabilities.WarnNoInterfaces)
	}
	state, _, loadErr := store.Load()
	d.Enrolled = loadErr == nil
	if d.Enrolled {
		d.AgentID, d.HomeID, d.APIURL = state.AgentID, state.HomeID, state.APIURL
	}
	if path := filepath.Join(*stateDir, queueFile); fileExists(path) {
		if q, err := queue.Open(path, queue.DefaultMaxBytes); err == nil {
			count, size, statErr := q.Stats(context.Background())
			q.Close()
			if statErr == nil {
				d.Queue = &queueStats{Messages: count, Bytes: size}
			}
		}
		if err := store.MatchOwner(); err != nil {
			fmt.Fprintf(stderr, "diagnose: warning: %v\n", err)
		}
	}
	if d.Enrolled && !*offline {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		info, err := agentauth.Service{Store: store}.Check(ctx)
		cancel()
		d.Backend = &backendCheck{Reachable: err == nil, HomeName: info.HomeName}
		if err != nil {
			d.Backend.Error = err.Error()
		}
		_ = store.MatchOwner()
	}

	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(d); err != nil {
			return fail(stderr, "diagnose", err)
		}
	} else {
		printDiagnosis(stdout, d, *offline)
	}
	switch {
	case !d.Enrolled:
		return ExitNotEnrolled
	case d.Backend != nil && !d.Backend.Reachable:
		return ExitError
	default:
		return ExitOK
	}
}

func printDiagnosis(w io.Writer, d diagnosis, offline bool) {
	yesNo := map[bool]string{true: "yes", false: "no"}
	fmt.Fprintf(w, "%s\n", d.Agent.String())
	fmt.Fprintf(w, "State directory: %s\n", d.StateDir)
	if d.Enrolled {
		fmt.Fprintf(w, "Enrollment:      enrolled (agent %s, home %s, %s)\n", d.AgentID, d.HomeID, d.APIURL)
	} else {
		fmt.Fprintln(w, "Enrollment:      not enrolled (run: shsc-agent enroll)")
	}
	fmt.Fprintf(w, "Service:         %s\n", d.Service)
	fmt.Fprintf(w, "Capabilities:    privileged=%s arp=%s icmp=%s\n", yesNo[d.Capabilities.Privileged],
		d.Capabilities.ARP, d.Capabilities.ICMP)
	warnings := "none"
	if len(d.Capabilities.Warnings) > 0 {
		warnings = strings.Join(d.Capabilities.Warnings, ", ")
	}
	fmt.Fprintf(w, "Warnings:        %s\n", warnings)
	fmt.Fprintln(w, "Interfaces:")
	if len(d.Interfaces) == 0 {
		fmt.Fprintln(w, "  (none usable)")
	}
	for _, i := range d.Interfaces {
		mac := i.MAC
		if mac == "" {
			mac = "-"
		}
		fmt.Fprintf(w, "  %-16s %-17s %s\n", i.Name, mac, strings.Join(i.Addresses, ", "))
	}
	if d.Queue != nil {
		fmt.Fprintf(w, "Local queue:     %d messages (%d bytes)\n", d.Queue.Messages, d.Queue.Bytes)
	} else {
		fmt.Fprintln(w, "Local queue:     not created yet")
	}
	switch {
	case d.Backend != nil && d.Backend.Reachable:
		fmt.Fprintf(w, "Backend:         reachable, authenticated (home %q)\n", d.Backend.HomeName)
	case d.Backend != nil:
		fmt.Fprintf(w, "Backend:         NOT reachable or rejected: %s\n", d.Backend.Error)
	case offline:
		fmt.Fprintln(w, "Backend:         not checked (--offline)")
	default:
		fmt.Fprintln(w, "Backend:         not checked (agent not enrolled)")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
