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
	"errors"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

// systemdNotifyReady sends a message to systemd to inform that we're ready.
func systemdNotifyReady() {
	_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)
}

// systemdNotifyReloading sends a message to systemd to inform that we're reloading.
func systemdNotifyReloading() {
	_, _ = daemon.SdNotify(false, daemon.SdNotifyReloading)
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
		return errors.New("found zero duration watchdog timer, ignoring")
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
	panic("unreachable")
}
