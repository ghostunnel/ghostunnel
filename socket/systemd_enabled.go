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

	"github.com/coreos/go-systemd/v22/activation"
)

func systemdSocket(name string) (net.Listener, error) {
	listeners, err := activation.ListenersWithNames()
	if err != nil {
		return nil, err
	}

	if listener, ok := listeners[name]; ok {
		if len(listeners) != 1 {
			return nil, fmt.Errorf("expected exactly 1 listening socket configured in systemd for name %s, found %d", name, len(listeners))
		}
		return listener[0], err
	}

	return nil, fmt.Errorf("expected listener with name %s, but found none", name)
}
