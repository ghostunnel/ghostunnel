// +build !darwin

package main

import (
	"errors"
	"net"
)

func LaunchdSocket() (net.Listener, error) {
	return nil, errors.New("launchd is only supported on darwin")
}
