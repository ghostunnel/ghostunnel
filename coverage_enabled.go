//go:build coverage

package main

import (
	"os"
	"runtime/coverage"
)

func init() {
	// Wrap exitFunc to flush coverage counters before exiting.
	// os.Exit does not run atexit handlers, so without this the
	// coverage data written by go build -cover would be lost.
	wrapped := exitFunc
	exitFunc = func(code int) {
		if dir := os.Getenv("GOCOVERDIR"); dir != "" {
			coverage.WriteCountersDir(dir)
		}
		wrapped(code)
	}

	// Register GOCOVERDIR as an extra RW path for landlock, so that
	// coverage counters can be written on Linux even with sandboxing.
	if dir := os.Getenv("GOCOVERDIR"); dir != "" {
		extraRWPaths = append(extraRWPaths, dir)
	}
}
