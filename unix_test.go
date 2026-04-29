//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/proxy"
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

// countingTLSConfigSource extends the failingTLSConfigSource with a counter
// for tracking Reload() invocations.
type countingTLSConfigSource struct {
	failingTLSConfigSource
	reloadCalls atomic.Int32
}

func (c *countingTLSConfigSource) Reload() error {
	c.reloadCalls.Add(1)
	return nil
}

// nopListener is a net.Listener whose Accept always errors, allowing a real
// proxy.Proxy to be constructed without binding any sockets.
type nopListener struct {
	closed chan struct{}
	once   sync.Once
}

func (l *nopListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, errors.New("listener closed")
}

func (l *nopListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *nopListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// TestSignalHandlerReloadAndShutdown drives both reachable branches of
// signalHandler's select loop on Unix: the SIGHUP refresh path (reload) and
// the shutdownChannel path. The serviceShutdownChan branch is unreachable on
// non-Windows because serviceShutdownChan() returns nil (see unix.go).
func TestSignalHandlerReloadAndShutdown(t *testing.T) {
	// Override exitFunc so the AfterFunc scheduled inside shutdownFunc
	// (signals.go ~line 54) does not kill the test process if the timer
	// happens to fire.
	origExit := exitFunc
	defer func() { exitFunc = origExit }()
	exitFunc = func(int) {}

	src := &countingTLSConfigSource{}
	sh := newStatusHandler(dummyDial, "test", "127.0.0.1:0", "127.0.0.1:0", "")
	env := &Environment{
		status:          sh,
		shutdownChannel: make(chan bool),
		shutdownTimeout: 5 * time.Second,
		tlsConfigSource: src,
	}

	lis := &nopListener{closed: make(chan struct{})}
	p := proxy.New(
		lis,
		time.Second, time.Second, time.Second,
		1,
		func(ctx context.Context) (net.Conn, error) {
			return nil, errors.New("nope")
		},
		logger,
		proxy.LogEverything,
		proxy.ProxyProtocolOff,
	)

	done := make(chan struct{})
	go func() {
		env.signalHandler(p)
		close(done)
	}()

	// Give the goroutine a moment to register signal.Notify before we
	// send SIGHUP. There is no synchronization seam exposed by
	// signalHandler, so a small fixed sleep is required here.
	time.Sleep(100 * time.Millisecond)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("failed to send SIGHUP: %v", err)
	}

	// Use Eventually-style polling for the reload counter to avoid flakes
	// on slow CI without a long fixed sleep.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if src.reloadCalls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, src.reloadCalls.Load(), int32(1),
		"expected at least one reload after SIGHUP")

	// Now trigger graceful shutdown via the channel.
	close(env.shutdownChannel)

	select {
	case <-done:
		// signalHandler returned as expected
	case <-time.After(2 * time.Second):
		t.Fatal("signalHandler did not return after shutdownChannel closed")
	}

	// The serviceShutdownChan branch (windows-only) is unreachable on Unix
	// because serviceShutdownChan() returns nil on non-Windows (see unix.go).
}
