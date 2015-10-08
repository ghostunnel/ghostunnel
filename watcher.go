package main

import (
	"syscall"

	"gopkg.in/fsnotify.v1"
)

func watch(files []string) {
	watcher, err := fsnotify.NewWatcher()
	panicOnError(err)

	for _, file := range files {
		watcher.Add(file)
	}

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				logger.Printf("found new %s, reloading", event.Name)
				syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
			}

		case err := <-watcher.Errors:
			logger.Printf("error watching file: %s", err)
		}
	}
}
