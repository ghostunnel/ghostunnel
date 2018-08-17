package copier

import (
	"bytes"
	"testing"

	mc "github.com/jordwest/mock-conn"
)

func TestSimpleCopier(t *testing.T) {
	backendConn := mc.NewConn()
	clientConn := mc.NewConn()

	defer backendConn.Close()
	defer clientConn.Close()

	// Copy data in the background
	cpForward := NewSimpleCopier(clientConn.Server, backendConn.Client, Forward)
	cpReverse := NewSimpleCopier(backendConn.Client, clientConn.Server, Reverse)
	go cpForward.Run()
	go cpReverse.Run()

	// Test that request written on client ends up proxied all the way to the backend
	msg0 := []byte("ping")
	clientConn.Client.Write(msg0)

	recv0 := make([]byte, len(msg0))
	backendConn.Server.Read(recv0)

	if !bytes.Equal(msg0, recv0) {
		t.Errorf("Expected to get %s, but got %s", string(msg0), string(recv0))
	}

	// Test that response from backend gets copied back to client
	msg1 := []byte("pong")
	backendConn.Server.Write(msg1)

	recv1 := make([]byte, len(msg1))
	clientConn.Client.Read(recv1)

	if !bytes.Equal(msg1, recv1) {
		t.Errorf("Expected to get %s, but got %s", string(msg0), string(recv0))
	}
}
