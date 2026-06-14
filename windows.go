//go:build windows

/*-
 * Copyright 2018 Square Inc.
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
	"bytes"
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var (
	shutdownSignals = []os.Signal{os.Interrupt}
	refreshSignals  = []os.Signal{ /* Not supported on Windows */ }
	eventlogFlag    = app.Flag("eventlog", "Send logs to Windows Event Log instead of stdout (Windows only).").Bool()

	// serviceStopCh is written to by the Windows Service Control Manager stop
	// handler to trigger a graceful shutdown of the running proxy.
	serviceStopCh = make(chan bool, 1)

	// serviceLogSource is the Event Log source name used by --eventlog. It
	// defaults to defaultServiceName so interactive invocations log to the
	// same source the default service install registers. runAsService
	// overrides it with the SCM-discovered name before calling svc.Run, so
	// runtime entries land on the source that doInstallService registered at
	// install time. svc.Run starts the service handler goroutine after this
	// assignment, so initSystemLogger (called from run()) observes the updated
	// value.
	serviceLogSource = defaultServiceName
)

func useSystemLog() bool {
	return *eventlogFlag
}

// eventLogWriter implements io.Writer for the Windows Event Log.
type eventLogWriter struct {
	handle windows.Handle
}

func newEventLogWriter(source string) (*eventLogWriter, error) {
	srcPtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return nil, err
	}
	h, err := windows.RegisterEventSource(nil, srcPtr)
	if err != nil {
		return nil, err
	}
	return &eventLogWriter{handle: h}, nil
}

func (w *eventLogWriter) Write(p []byte) (int, error) {
	msg := string(bytes.TrimRight(p, "\n"))
	msgPtr, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return 0, err
	}
	return len(p), windows.ReportEvent(w.handle, windows.EVENTLOG_INFORMATION_TYPE, 0, 1, 0, 1, 0, &msgPtr, nil)
}

func (w *eventLogWriter) Close() error {
	return windows.DeregisterEventSource(w.handle)
}

func initSystemLogger() error {
	w, err := newEventLogWriter(serviceLogSource)
	if err != nil {
		return err
	}
	logger = log.New(w, "", log.LstdFlags|log.Lmicroseconds)
	return nil
}

// serviceShutdownChan returns the channel that the Windows SCM stop handler
// signals when the service is asked to stop.
func serviceShutdownChan() <-chan bool {
	return serviceStopCh
}

// isRunningAsService reports whether the process was started by the Windows
// Service Control Manager rather than interactively.
func isRunningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// svcRun is the SCM dispatcher entry point. A package-level indirection so
// tests can simulate dispatcher failures without invoking the real
// StartServiceCtrlDispatcher (which only succeeds when the process was
// launched by the SCM). currentServiceName, called from runAsService just
// above this, still issues a best-effort mgr.Connect and gracefully falls
// back to defaultServiceName when the SCM is unavailable.
var svcRun = svc.Run

// runAsService hands control to the Windows Service Control Manager and
// returns when the dispatcher exits. A non-nil error from svcRun means
// StartServiceCtrlDispatcher itself failed (rare; e.g. SCM transient or
// malformed name pointer) — never an error reported by Execute, which the
// dispatcher conveys to SCM via the SERVICE_STATUS struct. We surface the
// failure to the Event Log (best-effort), stderr (null under SCM but useful
// for manual repro), and process exit code so the services console shows a
// non-zero ExitCode instead of a silent 0.
func runAsService() {
	serviceLogSource = currentServiceName()
	if err := svcRun(serviceLogSource, &ghostunnelService{name: serviceLogSource}); err != nil {
		msg := fmt.Sprintf("ghostunnel SCM dispatcher failed: %v", err)
		writeEventLogError(serviceLogSource, msg)
		fmt.Fprintln(os.Stderr, "error: "+msg)
		exitFunc(1)
	}
}
