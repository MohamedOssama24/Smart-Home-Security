package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const localService = `NT AUTHORITY\LocalService`

// Install registers the Windows service (LocalService, delayed automatic start, restart
// after failures) and starts it. Requires an elevated prompt.
func Install(c Config, out io.Writer) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return fmt.Errorf("service %s is already installed", Name)
	}
	s, err := m.CreateService(Name, c.Executable, mgr.Config{
		DisplayName:      DisplayName,
		Description:      Description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: localService,
	}, "run", "--state-dir", c.StateDir)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}
	if err := s.SetRecoveryActions(actions, uint32((24 * time.Hour).Seconds())); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	// a non-zero exit code also counts as a failure (a revoked agent exits with 0)
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Fprintf(out, "Service %s installed and started (account LocalService).\nLog: %s\\agent.log\n", Name, c.StateDir)
	return nil
}

// Uninstall stops and deletes the service. The identity is kept.
func Uninstall(c Config, out io.Writer) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", Name)
	}
	defer s.Close()
	if err := stopAndWait(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Fprintf(out, "Service %s removed. The identity is still in %s (delete it to forget this agent).\n", Name, c.StateDir)
	return nil
}

// Start starts the installed service.
func Start() error {
	return withService(func(s *mgr.Service) error { return s.Start() })
}

// Stop stops the installed service and waits for it.
func Stop() error {
	return withService(stopAndWait)
}

// Status returns the state of the service. It needs only read access, so it also works
// from a non-elevated prompt (mgr.Connect would ask for full control of the SCM).
func Status() (string, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		return "", err
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "not installed", nil
	}
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return "", err
	}
	return map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping",
		svc.Running: "running", svc.ContinuePending: "resuming", svc.PausePending: "pausing",
		svc.Paused: "paused"}[svc.State(st.CurrentState)], nil
}

var errNotInstalled = errors.New("service not installed")

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, errors.New("access denied: run this command from an elevated (administrator) prompt")
		}
		return nil, err
	}
	return m, nil
}

func withService(f func(*mgr.Service) error) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return errNotInstalled
	}
	defer s.Close()
	return f(s)
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("the service did not stop within 30 seconds")
}

// IsWindowsService reports whether the process was started by the Service Control Manager.
func IsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

// RunWindowsService runs the agent loop under the Service Control Manager. run must return
// nil for a clean stop (including a revocation): the service then stops without being
// restarted; an error is reported as a failure and triggers the recovery actions.
func RunWindowsService(run func(context.Context) error) error {
	return svc.Run(Name, handler{run: run})
}

type handler struct {
	run func(context.Context) error
}

func (h handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done:
			if err != nil {
				return true, 1 // service-specific failure: recovery actions restart it
			}
			return false, 0
		}
	}
}
