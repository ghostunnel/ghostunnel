//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

// isWindowsAdmin reports whether the current process has Administrator
// privileges, which are required for service management operations.
func isWindowsAdmin() bool {
	const keyCreateSubKey = 0x00000004
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`,
		keyCreateSubKey)
	if err != nil {
		return false
	}
	key.Close()
	return true
}

func TestValidateServiceName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ghostunnel", false},
		{"my-service", false},
		{"my_service", false},
		{"My Service", false},
		{"a", false},
		{"", true},
		{string(make([]byte, 257)), true},
		{"bad/name", true},
		{"bad\\name", true},
		{"bad<name>", true},
		{"bad@name", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServiceName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateServiceName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestCurrentServiceNameNotService(t *testing.T) {
	if isRunningAsService() {
		t.Skip("running as a Windows service")
	}
	if got := currentServiceName(); got != defaultServiceName {
		t.Errorf("currentServiceName() = %q, want %q", got, defaultServiceName)
	}
}

func TestStatusNonExistentService(t *testing.T) {
	if err := doStatusService("ghostunnel-nonexistent-99999"); err == nil {
		t.Error("expected error for non-existent service, got nil")
	}
}

// TestServiceLifecycle exercises the full install→status→stop→uninstall
// cycle against the real Windows Service Control Manager.
func TestServiceLifecycle(t *testing.T) {
	if !isWindowsAdmin() {
		t.Skip("requires Administrator privileges")
	}

	const name = "ghostunnel-integration-test"

	// Use "service status" as the proxy args so the service process exits
	// promptly without needing TLS certificates. We are testing SCM
	// registration, not proxy connectivity.
	proxyArgs := []string{"service", "status", "--service-name", name}

	t.Cleanup(func() {
		_ = doUninstallService(name) // best-effort cleanup on failure
	})

	// When running under "go test", os.Executable() returns the test binary
	// rather than ghostunnel.exe. The SCM will fail to start it as a Windows
	// service because testing.Main() never registers a service control handler.
	// We tolerate that specific error and verify the SCM registration itself.
	installErr := doInstallService(name, proxyArgs)
	if installErr != nil && !errors.Is(installErr, errServiceNotStarted) {
		t.Fatalf("install: %v", installErr)
	}

	// If install failed during waitForServiceRunning, the registration has
	// been rolled back automatically; nothing more to test or clean up.
	statusErr := doStatusService(name)
	if installErr != nil && statusErr != nil {
		return
	}
	if statusErr != nil {
		t.Errorf("status after install: %v", statusErr)
	}

	// Service will be stopped already (never started); stopServiceWithTimeout
	// handles the already-stopped case gracefully.
	if err := doStopService(name); err != nil {
		t.Errorf("stop: %v", err)
	}

	if err := doUninstallService(name); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	// Service must be gone after uninstall.
	if err := doStatusService(name); err == nil {
		t.Error("expected error querying service after uninstall, got nil")
	}
}

// waitForServiceRunningPoll is exercised here without a real SCM by injecting
// a scripted query function. Tests use zero or near-zero durations to keep
// runtime negligible.

type pollStep struct {
	state svc.State
	err   error
}

func newScriptedQuery(steps []pollStep) func() (svc.Status, error) {
	i := 0
	return func() (svc.Status, error) {
		if i >= len(steps) {
			return svc.Status{}, fmt.Errorf("query called more times than scripted (%d)", len(steps))
		}
		step := steps[i]
		i++
		return svc.Status{State: step.state}, step.err
	}
}

func TestWaitForServiceRunningPoll(t *testing.T) {
	queryFailure := errors.New("scripted query failure")

	tests := []struct {
		name      string
		steps     []pollStep
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "running immediately",
			steps:   []pollStep{{state: svc.Running}},
			wantErr: false,
		},
		{
			name:    "start pending then running",
			steps:   []pollStep{{state: svc.StartPending}, {state: svc.Running}},
			wantErr: false,
		},
		{
			name:    "continue pending then running",
			steps:   []pollStep{{state: svc.ContinuePending}, {state: svc.Running}},
			wantErr: false,
		},
		{
			name:      "stopped immediately",
			steps:     []pollStep{{state: svc.Stopped}},
			wantErr:   true,
			errSubstr: "failed to reach running state",
		},
		{
			name:      "stop pending fails fast",
			steps:     []pollStep{{state: svc.StopPending}},
			wantErr:   true,
			errSubstr: "failed to reach running state",
		},
		{
			name:      "paused fails fast",
			steps:     []pollStep{{state: svc.Paused}},
			wantErr:   true,
			errSubstr: "failed to reach running state",
		},
		{
			name:      "query error",
			steps:     []pollStep{{err: queryFailure}},
			wantErr:   true,
			errSubstr: "could not query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := newScriptedQuery(tt.steps)
			// Zero poll keeps the test instantaneous; a generous timeout
			// ensures the loop never trips the deadline before the scripted
			// query yields a terminal state.
			err := waitForServiceRunningPoll("test-service", query, 0, time.Minute)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("err = %q, want substring %q", err, tt.errSubstr)
			}
		})
	}
}

func TestWaitForServiceRunningPollTimeout(t *testing.T) {
	// Always-StartPending query forces the loop to rely on the deadline check.
	// A 1ms poll bound prevents busy-looping while still keeping the test fast.
	query := func() (svc.Status, error) {
		return svc.Status{State: svc.StartPending}, nil
	}

	err := waitForServiceRunningPoll("test-service", query, time.Millisecond, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %q, want timeout message", err)
	}
}
