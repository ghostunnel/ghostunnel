//go:build linux

package socket

import (
	"net"
	"os"
	"path/filepath"
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

// TestSystemdInheritedUnixSocketNotUnlinkedOnClose documents the contract that
// clientListen/serverListen rely on: a UNIX listener inherited from systemd
// (built via net.FileListener, as activation.ListenersWithNames does
// internally) must not unlink the socket path on Close. The service manager
// owns the path and may recreate the listener across exec restarts; unlinking
// it from the child breaks that handoff and destroys the unit's SocketUser /
// SocketGroup / SocketMode settings.
func TestSystemdInheritedUnixSocketNotUnlinkedOnClose(t *testing.T) {
	// Short tmpdir keeps the path under the AF_UNIX sun_path limit.
	tmpDir, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	sockPath := filepath.Join(tmpDir, "test.sock")

	// Mimic systemd's setup: an outer process binds the socket and would not
	// unlink it on its own exit.
	parent, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	parent.(*net.UnixListener).SetUnlinkOnClose(false)
	defer parent.Close()

	f, err := parent.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// activation.ListenersWithNames produces child listeners exactly this way.
	inherited, err := net.FileListener(f)
	if err != nil {
		t.Fatal(err)
	}

	result, err := systemdSocketFromMap("test", map[string][]net.Listener{
		"test": {inherited},
	})
	assert.Nil(t, err)

	// Closing the inherited listener (as graceful shutdown does) must leave
	// the path in place.
	assert.Nil(t, result.Close())

	_, err = os.Stat(sockPath)
	assert.NoError(t, err, "systemd-inherited UNIX socket must not be unlinked on Close")
}
