//go:build !linux && !windows

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

// notifyServiceStatus sends a message to systemd to inform that we're ready.
func notifyServiceStatus(_ string) {}

// notifyServiceReady sends a message to systemd to inform that we're ready.
func notifyServiceReady() {}

// notifyServiceReloading sends a message to systemd to inform that we're reloading.
func notifyServiceReloading() {}

// notifyServiceStopping sends a message to systemd to inform that we're stopping.
func notifyServiceStopping() {}

// handleServiceWatchdog sends watchdog messages to systemd to keep us alive, if enabled.
func handleServiceWatchdog(isHealthy func() bool, shutdown chan bool) error {
	return nil
}
