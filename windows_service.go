//go:build windows

/*-
 * Copyright 2024, Ghostunnel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"os"
	"time"
	"unicode"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceNameFlagName = "service-name"
	defaultServiceName  = "ghostunnel"
)

var (
	serviceCmd          = app.Command("service", "Manage ghostunnel as a Windows service (requires Administrator).")
	serviceInstallCmd   = serviceCmd.Command("install", "Install and start ghostunnel as a Windows service.")
	serviceUninstallCmd = serviceCmd.Command("uninstall", "Stop and remove the ghostunnel Windows service.")
	serviceStartCmd     = serviceCmd.Command("start", "Start the ghostunnel Windows service.")
	serviceStopCmd      = serviceCmd.Command("stop", "Stop the ghostunnel Windows service.")
	serviceStatusCmd    = serviceCmd.Command("status", "Show the status of the ghostunnel Windows service.")

	// Each subcommand carries its own --service-name flag so the flag can
	// appear after the subcommand name on the command line, e.g.:
	//   ghostunnel service install --service-name mysvc -- server ...
	serviceInstallName   = serviceInstallCmd.Flag(serviceNameFlagName, "Name to use for the Windows service.").Default(defaultServiceName).String()
	serviceUninstallName = serviceUninstallCmd.Flag(serviceNameFlagName, "Name to use for the Windows service.").Default(defaultServiceName).String()
	serviceStartName     = serviceStartCmd.Flag(serviceNameFlagName, "Name to use for the Windows service.").Default(defaultServiceName).String()
	serviceStopName      = serviceStopCmd.Flag(serviceNameFlagName, "Name to use for the Windows service.").Default(defaultServiceName).String()
	serviceStatusName    = serviceStatusCmd.Flag(serviceNameFlagName, "Name to use for the Windows service.").Default(defaultServiceName).String()

	// Proxy arguments stored in the service registration; everything after '--'.
	serviceInstallArgs = serviceInstallCmd.Arg("args", "Proxy arguments to pass to the service, separated from service flags by '--' (e.g. -- server --listen :8443 --target localhost:8080).").Strings()

)

// currentServiceName discovers the name of the Windows service for the current
// process by matching PIDs via the SCM. Returns defaultServiceName on failure.
func currentServiceName() string {
	m, err := mgr.Connect()
	if err != nil {
		return defaultServiceName
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return defaultServiceName
	}

	myPID := uint32(os.Getpid())
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		status, err := s.Query()
		s.Close()
		if err != nil {
			continue
		}
		if status.ProcessId == myPID {
			return name
		}
	}
	return defaultServiceName
}

// ghostunnelService implements svc.Handler so the Windows Service Control
// Manager can start, stop, and interrogate the process.
type ghostunnelService struct {
	name string
}

func (s *ghostunnelService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	elog, _ := eventlog.Open(s.name) // best-effort; non-critical if event source not registered
	if elog != nil {
		defer elog.Close()
	}

	changes <- svc.Status{State: svc.StartPending}

	done := make(chan error, 1)
	go func() {
		done <- run(os.Args[1:])
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	if elog != nil {
		_ = elog.Info(1, "ghostunnel service started")
	}

	for {
		select {
		case err := <-done:
			// ghostunnel exited on its own (e.g. configuration error).
			if err != nil {
				if elog != nil {
					_ = elog.Error(1, fmt.Sprintf("ghostunnel exited with error: %v", err))
				}
				return false, 1
			}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				if elog != nil {
					_ = elog.Info(1, "ghostunnel service stopping")
				}
				serviceStopCh <- true
				<-done // wait for graceful drain to complete
				return false, 0
			}
		}
	}
}

func validateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("service name cannot be empty")
	}
	if len(name) > 256 {
		return fmt.Errorf("service name must be 256 characters or fewer")
	}
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' && c != ' ' {
			return fmt.Errorf("service name contains invalid character %q (allowed: letters, digits, hyphens, underscores, spaces)", c)
		}
	}
	return nil
}

// checkGhostunnelMarker returns an error if the named service was not installed
// by ghostunnel's own service management commands.
func checkGhostunnelMarker(name string) error {
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+name+`\Parameters`,
		registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("service %q does not appear to be managed by ghostunnel (registry marker missing)", name)
	}
	val, _, err := regKey.GetIntegerValue("GhostunnelManaged")
	regKey.Close()
	if err != nil || val != 1 {
		return fmt.Errorf("service %q does not appear to be managed by ghostunnel (registry marker missing)", name)
	}
	return nil
}

// stopServiceWithTimeout sends a stop control to the service and waits up to
// 30 seconds for it to reach the Stopped state.
func stopServiceWithTimeout(s *mgr.Service, name string) error {
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("could not query service %q: %w", name, err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("could not stop service %q: %w", name, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service %q to stop", name)
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return fmt.Errorf("could not query service %q: %w", name, err)
		}
	}
	return nil
}

func doInstallService(name string, proxyArgs []string) error {
	if err := validateServiceName(name); err != nil {
		return err
	}
	if len(proxyArgs) == 0 {
		return fmt.Errorf("no proxy arguments provided; use: ghostunnel service install [--service-name NAME] -- server|client [ARGS...]")
	}

	exepath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(name, exepath, mgr.Config{
		DisplayName: "Ghostunnel (" + name + ")",
		StartType:   mgr.StartAutomatic,
		Description: "Ghostunnel TLS proxy service.",
	}, proxyArgs...)
	if err != nil {
		return fmt.Errorf("could not create service %q: %w", name, err)
	}
	defer s.Close()

	// Register an event source so Windows Event Log doesn't show
	// "The description for Event ID X from source ghostunnel cannot be found."
	if err := eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		// Non-fatal: the service will still work, log entries just look ugly.
		fmt.Fprintf(os.Stderr, "warning: could not register event log source: %v\n", err)
	}

	// Write a registry marker so uninstall can confirm this service was
	// installed by ghostunnel and not some other application.
	regKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+name+`\Parameters`,
		registry.SET_VALUE)
	if err != nil {
		_ = s.Delete()
		return fmt.Errorf("could not write registry marker for service %q: %w", name, err)
	}
	if err := regKey.SetDWordValue("GhostunnelManaged", 1); err != nil {
		regKey.Close()
		_ = s.Delete()
		return fmt.Errorf("could not write registry marker for service %q: %w", name, err)
	}
	regKey.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("service %q installed but could not be started: %w", name, err)
	}

	fmt.Printf("Service %q installed and started successfully.\n", name)
	return nil
}

func doUninstallService(name string) error {
	if err := validateServiceName(name); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not open service %q: %w", name, err)
	}
	defer s.Close()

	if err := checkGhostunnelMarker(name); err != nil {
		return err
	}

	if err := stopServiceWithTimeout(s, name); err != nil {
		return err
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("could not delete service %q: %w", name, err)
	}

	if elog, err := eventlog.Open(name); err == nil {
		_ = elog.Info(1, fmt.Sprintf("ghostunnel service %q uninstalled", name))
		elog.Close()
	}
	_ = eventlog.Remove(name) // best-effort; non-critical

	fmt.Printf("Service %q stopped and removed successfully.\n", name)
	return nil
}

func doStartService(name string) error {
	if err := validateServiceName(name); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not open service %q: %w", name, err)
	}
	defer s.Close()

	if err := checkGhostunnelMarker(name); err != nil {
		return err
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("could not start service %q: %w", name, err)
	}

	fmt.Printf("Service %q started successfully.\n", name)
	return nil
}

func doStopService(name string) error {
	if err := validateServiceName(name); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not open service %q: %w", name, err)
	}
	defer s.Close()

	if err := checkGhostunnelMarker(name); err != nil {
		return err
	}

	if err := stopServiceWithTimeout(s, name); err != nil {
		return err
	}

	fmt.Printf("Service %q stopped successfully.\n", name)
	return nil
}

func doStatusService(name string) error {
	if err := validateServiceName(name); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", name, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("could not query service %q: %w", name, err)
	}

	stateStr := "unknown"
	switch status.State {
	case svc.Stopped:
		stateStr = "stopped"
	case svc.StartPending:
		stateStr = "start pending"
	case svc.StopPending:
		stateStr = "stop pending"
	case svc.Running:
		stateStr = "running"
	case svc.ContinuePending:
		stateStr = "continue pending"
	case svc.PausePending:
		stateStr = "pause pending"
	case svc.Paused:
		stateStr = "paused"
	}

	fmt.Printf("Service %q: %s (PID %d)\n", name, stateStr, status.ProcessId)
	return nil
}

func runServiceCommand(command string) (bool, error) {
	switch command {
	case serviceInstallCmd.FullCommand():
		return true, doInstallService(*serviceInstallName, *serviceInstallArgs)
	case serviceUninstallCmd.FullCommand():
		return true, doUninstallService(*serviceUninstallName)
	case serviceStartCmd.FullCommand():
		return true, doStartService(*serviceStartName)
	case serviceStopCmd.FullCommand():
		return true, doStopService(*serviceStopName)
	case serviceStatusCmd.FullCommand():
		return true, doStatusService(*serviceStatusName)
	}
	return false, nil
}
