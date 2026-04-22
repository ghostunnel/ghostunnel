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
