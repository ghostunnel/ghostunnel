// Package copier provides interfaces for copiers, which copy data between a
// dst/src network connection, optionally logging or filtering the data.
package copier

import (
	"io"
	"net"
)

// Direction indicates if we're copying in the forward (client to server) or
// reverse (server to client) direction of a connection.
type Direction int

const (
	// Forward means data is flowing from client to server (request data).
	Forward Direction = 0
	// Reverse means data is flowing from server to client (response data).
	Reverse Direction = 1
)

// Plugin represents a loadable plugin that can provide a type of copier.
type Plugin interface {
	// Instantiate a new copier for a connection tuple.
	NewCopier(dst, src net.Conn, direction Direction) Copier
}

type Copier interface {
	Run() error
}

type SimpleCopier struct {
	dst, src net.Conn
}

// NewSimpleCopier returns a copier that simply copies data from one connection
// to the other, without logging or filtering anything.
func NewSimpleCopier(dst, src net.Conn, direction Direction) Copier {
	return SimpleCopier{dst, src}
}

func (sc SimpleCopier) Run() error {
	_, err := io.Copy(sc.dst, sc.src)
	return err
}
