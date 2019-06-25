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
	"net"
	"strings"

	reuseport "github.com/kavu/go_reuseport"
)

// ParseAddress parses a string representing a TCP address or UNIX socket
// for our backend target. The input can be or the form "HOST:PORT" for
// a TCP socket, "unix:PATH" for a UNIX socket, and "systemd:NAME" or
// "launchd:NAME" for a socket provided by launchd/systemd for socket
// activation.
func ParseAddress(input string) (network, address, host string, err error) {
	if strings.HasPrefix(input, "launchd:") {
		network = "launchd"
		address = input[8:]
		return
	}

	if strings.HasPrefix(input, "systemd:") {
		network = "systemd"
		address = input[8:]
		return
	}

	if strings.HasPrefix(input, "unix:") {
		network = "unix"
		address = input[5:]
		return
	}

	host, _, err = net.SplitHostPort(input)
	if err != nil {
		return
	}

	// Make sure target address resolves
	_, err = net.ResolveTCPAddr("tcp", input)
	if err != nil {
		return
	}

	network, address = "tcp", input
	return
}

// Open a listening socket with the given network and address.
// Supports 'unix', 'tcp', 'launchd' and 'systemd' as the network.
//
// For 'tcp' sockets, the address must be a host and a port. The
// opened socket will be bound with SO_REUSEPORT.
//
// For 'unix' sockets, the address must be a path. The socket file
// will be set to unlink on close automatically.
//
// For 'launchd' sockets, the address must be the name of the socket
// from the plist file. Only one socket maybe configured in the
// plist for that name, multiple sockets per name (e.g. separate
// IPv4/IPv4 sockets) are not supported.
//
// For 'systemd' sockets, the address must be the name of the socket.
// In the systemd unit file, the FileDescriptorName option must be
// set and needs to match the address string.
func Open(network, address string) (net.Listener, error) {
	switch network {
	case "launchd":
		return launchdSocket(address)
	case "systemd":
		return systemdSocket(address)
	case "unix":
		listener, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		listener.(*net.UnixListener).SetUnlinkOnClose(true)
		return listener, nil
	default:
		return reuseport.NewReusablePortListener(network, address)
	}
}

// ParseAndOpen combines the functionality of the ParseAddress and Open methods.
func ParseAndOpen(address string) (net.Listener, error) {
	net, addr, _, err := ParseAddress(address)
	if err != nil {
		return nil, err
	}
	return Open(net, addr)
}
