//go:build linux

/*-
 * Copyright 2019 Square Inc.
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

package socket

import (
	"fmt"
	"net"
	"sync"

	"github.com/coreos/go-systemd/v22/activation"
)

// activation.ListenersWithNames consumes the LISTEN_FDS environment on first
// call (so the fds aren't inherited by child processes), which means we can
// only ask the activation library for sockets once. Cache the result so
// callers requesting different names (e.g. --listen=systemd:foo and
// --status=systemd:bar) all see the full set.
var (
	systemdListenersOnce sync.Once
	systemdListeners     map[string][]net.Listener
	systemdListenersErr  error
)

func systemdSocket(name string) (net.Listener, error) {
	systemdListenersOnce.Do(func() {
		systemdListeners, systemdListenersErr = activation.ListenersWithNames()
	})
	if systemdListenersErr != nil {
		return nil, systemdListenersErr
	}

	return systemdSocketFromMap(name, systemdListeners)
}

func systemdSocketFromMap(name string, listeners map[string][]net.Listener) (net.Listener, error) {
	if listener, ok := listeners[name]; ok {
		if len(listener) != 1 {
			return nil, fmt.Errorf("expected exactly 1 listening socket configured in systemd for name %s, found %d", name, len(listener))
		}
		return listener[0], nil
	}

	return nil, fmt.Errorf("expected listener with name %s, but found none", name)
}
