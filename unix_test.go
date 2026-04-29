//go:build !windows

package main

import (
	"errors"
	"testing"

	gsyslog "github.com/hashicorp/go-syslog"
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

func TestInitSystemLoggerError(t *testing.T) {
	originalLogger := logger
	originalNew := newSyslogger
	defer func() {
		logger = originalLogger
		newSyslogger = originalNew
	}()

	sentinel := errors.New("syslog dial failed")
	newSyslogger = func(p gsyslog.Priority, facility, tag string) (gsyslog.Syslogger, error) {
		return nil, sentinel
	}

	err := initSystemLogger()
	assert.Error(t, err)
	assert.Equal(t, sentinel, err)
	assert.Equal(t, originalLogger, logger, "logger must not be mutated on failure")
}
