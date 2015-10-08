/*-
 * Copyright 2015 Square Inc.
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

package main

import (
	"path"
	"syscall"

	"gopkg.in/fsnotify.v1"
)

func watch(files []string) {
	watcher, err := fsnotify.NewWatcher()
	panicOnError(err)

	for _, file := range files {
		watcher.Add(path.Dir(file))
	}

	for {
		select {
		case event := <-watcher.Events:
			for _, file := range files {
				if event.Name == path.Base(file) {
					logger.Printf("detected change on %s, reloading", event.Name)
					syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
					break
				}
			}

		case err := <-watcher.Errors:
			logger.Printf("error watching file: %s", err)
		}
	}
}
