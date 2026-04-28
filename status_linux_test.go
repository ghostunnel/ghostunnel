//go:build linux

package main

import "testing"

func TestGetMonotonicUsec(t *testing.T) {
	usec, err := getMonotonicUsec()
	if err != nil {
		t.Fatalf("getMonotonicUsec returned unexpected error: %v", err)
	}
	if usec <= 0 {
		t.Errorf("getMonotonicUsec returned non-positive value: %d", usec)
	}
}

func TestNotifyServiceReloadingDoesNotPanic(t *testing.T) {
	// Should not panic even if systemd is not available
	notifyServiceReloading()
}
