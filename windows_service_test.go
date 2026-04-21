//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
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
	if err := doInstallService(name, proxyArgs); err != nil {
		if !strings.Contains(err.Error(), "installed but could not be started") {
			t.Fatalf("install: %v", err)
		}
	}

	// Service should be registered in the SCM regardless of whether it started.
	if err := doStatusService(name); err != nil {
		t.Errorf("status after install: %v", err)
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
