//go:build linux

/*-
 * Copyright 2024, Ghostunnel
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
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/coreos/go-systemd/v22/daemon"
)

const (
	clock_monotonic_clkid = 1
)

// getMonotonicUsec gets time via CLOCK_MONOTONIC for reload messages
func getMonotonicUsec() int64 {
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clock_monotonic_clkid, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		panic("Unable to get current time from SYS_CLOCK_GETTIME")
	}
	sec, nsec := ts.Unix()
	// 1s is 1e6µs, 1ns is 1/1000µs
	return (sec * 1e6) + (nsec / 1000)
}

// systemdNotifyStatus sends a message to systemd to inform that we're ready.
func systemdNotifyStatus(status string) {
	msg := fmt.Sprintf("STATUS=%s", status)
	_, _ = daemon.SdNotify(false, msg)
}

// systemdNotifyReady sends a message to systemd to inform that we're ready.
func systemdNotifyReady() {
	_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)
}

// systemdNotifyReloading sends a message to systemd to inform that we're reloading.
func systemdNotifyReloading() {
	msg := fmt.Sprintf("%s\nMONOTONIC_USEC=%d", daemon.SdNotifyReloading, getMonotonicUsec())
	_, _ = daemon.SdNotify(false, msg)
}

// systemdNotifyStopping sends a message to systemd to inform that we're stopping.
func systemdNotifyStopping() {
	_, _ = daemon.SdNotify(false, daemon.SdNotifyStopping)
}

// systemdHandleWatchdog sends watchdog messages to systemd to keep us alive, if enabled.
func systemdHandleWatchdog(isHealthy func() bool, shutdown chan bool) error {
	dur, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		return err
	}
	if dur == 0 {
		// Watchdog not enabled, ignore
		return nil
	}
	ticker := time.NewTicker(dur / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if isHealthy() {
				_, _ = daemon.SdNotify(false, daemon.SdNotifyWatchdog)
			}
		case <-shutdown:
			return nil
		}
	}
	//nolint:govet
	panic("unreachable")
}
