//go:build linux

package socket

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSystemdSocketMultipleNames(t *testing.T) {
	// Two systemd socket names, each with exactly one listener.
	// Requesting "web" should succeed since "web" has exactly 1 socket.
	webListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer webListener.Close()

	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer apiListener.Close()

	listeners := map[string][]net.Listener{
		"web": {webListener},
		"api": {apiListener},
	}

	result, err := systemdSocketFromMap("web", listeners)
	assert.Nil(t, err, "requesting 'web' with 1 socket should succeed even when other names exist")
	assert.Equal(t, webListener, result)
}

func TestSystemdSocketMultipleSocketsSameName(t *testing.T) {
	// One systemd socket name with two listeners.
	// This should fail since we expect exactly 1 socket per name.
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	listeners := map[string][]net.Listener{
		"web": {l1, l2},
	}

	_, err = systemdSocketFromMap("web", listeners)
	assert.NotNil(t, err, "should fail when a name has multiple sockets")
}
