package main

import (
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/kardianos/osext"
)

// Reload the process by spawning a child. This reloads the binary as well
// as certificates and keys. The child process will start up, attempt to
// open the socket with SO_REUSEPORT, and start listening. Once the listening
// socket is open, the child will send SIGTERM to the parent. The parent will
// catch the SIGTERM and gracefully shut down.
func reexec() {
	path, err := osext.Executable()
	if err != nil {
		log.Printf("Failed to get executable path: %s", err)
	}

	args := []string{"--graceful"}
	for _, val := range os.Args[1:] {
		if val != "--graceful" {
			args = append(args, val)
		}
	}

	log.Printf("Executing self: %s %s", path, strings.Join(args, " "))

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

	if err != nil {
		log.Printf("Child failed with error: %s", err)
	}
}
