//go:build windows

package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows/svc"
)

func TestUseSystemLog(t *testing.T) {
	assert.False(t, useSystemLog(), "useSystemLog should default to false")
}

func TestEventLogWriterWriteAndClose(t *testing.T) {
	w, err := newEventLogWriter("Application")
	if err != nil {
		t.Fatalf("newEventLogWriter failed: %s", err)
	}
	defer w.Close()

	n, err := w.Write([]byte("ghostunnel test message\n"))
	assert.Nil(t, err)
	assert.Equal(t, len("ghostunnel test message\n"), n)
}

func TestInitSystemLogger(t *testing.T) {
	originalLogger := logger
	defer func() { logger = originalLogger }()

	err := initSystemLogger()
	if err != nil {
		t.Fatalf("initSystemLogger failed: %s", err)
	}
	assert.NotEqual(t, originalLogger, logger, "logger should be updated")
	assert.NotNil(t, logger)
}

// TestRunAsServiceSurfacesDispatcherError verifies that a non-nil error from
// the SCM dispatcher results in a non-zero exit via exitFunc, rather than
// being silently swallowed. The svcRun seam avoids invoking the real
// StartServiceCtrlDispatcher; currentServiceName still runs but falls back
// gracefully when the SCM cannot be reached.
func TestRunAsServiceSurfacesDispatcherError(t *testing.T) {
	origRun := svcRun
	origExit := exitFunc
	origSource := serviceLogSource
	t.Cleanup(func() {
		svcRun = origRun
		exitFunc = origExit
		serviceLogSource = origSource
	})

	exitCode := -1
	exitFunc = func(c int) { exitCode = c }
	svcRun = func(string, svc.Handler) error {
		return errors.New("scripted dispatch failure")
	}

	runAsService()

	assert.Equal(t, 1, exitCode, "exitFunc should be called with 1 on dispatcher failure")
}

// TestRunAsServiceSilentOnSuccess verifies the success path leaves exitFunc
// uncalled, so main() returns 0 the normal way.
func TestRunAsServiceSilentOnSuccess(t *testing.T) {
	origRun := svcRun
	origExit := exitFunc
	origSource := serviceLogSource
	t.Cleanup(func() {
		svcRun = origRun
		exitFunc = origExit
		serviceLogSource = origSource
	})

	exitCalled := false
	exitFunc = func(int) { exitCalled = true }
	svcRun = func(string, svc.Handler) error { return nil }

	runAsService()

	assert.False(t, exitCalled, "exitFunc must not be called when svcRun succeeds")
}

// TestInitSystemLoggerUsesServiceLogSource verifies that initSystemLogger opens
// the Event Log source named by serviceLogSource — the variable Execute updates
// from the SCM-supplied args[0] before spawning the proxy goroutine — rather
// than a hardcoded source.
func TestInitSystemLoggerUsesServiceLogSource(t *testing.T) {
	originalLogger := logger
	originalSource := serviceLogSource
	t.Cleanup(func() {
		logger = originalLogger
		serviceLogSource = originalSource
	})

	// "Application" is a built-in Event Log that is always registerable as an
	// event source, so the test doesn't depend on prior service installation.
	serviceLogSource = "Application"
	if err := initSystemLogger(); err != nil {
		t.Fatalf("initSystemLogger with serviceLogSource=%q failed: %s", serviceLogSource, err)
	}
	assert.NotEqual(t, originalLogger, logger, "logger should be updated")
}
