//go:build !windows

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUseSystemLog(t *testing.T) {
	assert.False(t, useSystemLog(), "useSystemLog should default to false")
}

func TestInitSystemLoggerSuccess(t *testing.T) {
	originalLogger := logger
	defer func() { logger = originalLogger }()

	err := initSystemLogger()
	if err != nil {
		t.Logf("syslog not available, skipping: %s", err)
		t.SkipNow()
		return
	}
	assert.NotEqual(t, originalLogger, logger, "logger should be updated")
	assert.NotNil(t, logger)
}
