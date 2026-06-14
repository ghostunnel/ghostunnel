//go:build windows

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

// TestInitSystemLoggerUsesServiceLogSource verifies that initSystemLogger opens
// the Event Log source named by serviceLogSource — the variable runAsService
// seeds with the SCM-registered service name — rather than a hardcoded source.
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
