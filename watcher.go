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
	"bytes"
	"crypto/sha256"
	"io/ioutil"
	"path"
	"time"

	"gopkg.in/fsnotify.v1"
)

// Watch files using inotify/fswatch.
func watchAuto(files []string, notify chan bool) {
	watcher, err := fsnotify.NewWatcher()
	panicOnError(err)

	for _, file := range files {
		// Need to watch both directory and file, because we want to detect
		// files being overwritten (gives Write event) but also files being
		// removed/re-added.
		watcher.Add(file)
		watcher.Add(path.Dir(file))
	}

	for {
		select {
		case event := <-watcher.Events:
			for _, file := range files {
				if path.Base(event.Name) == path.Base(file) {
					logger.Printf("detected change on %s, reloading", event.Name)
					notify <- true

					// If we get Create event, it's probably because the file was
					// removed and then re-added. Need to re-register for events
					// on file or we won't get them in the future.
					if event.Op&fsnotify.Create == fsnotify.Create {
						watcher.Add(file)
					}

					break
				}
			}

		case err := <-watcher.Errors:
			logger.Printf("error watching file: %s", err)
		}
	}
}

// Watch files with a periodic timer, for filesystems that don't do
// inotify correctly (e.g. some fuse filesystems or other custom stuff).
func watchTimed(files []string, duration time.Duration, notify chan bool) {
	hashes := make([][32]byte, len(files))
	for i, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			logger.Printf("error watching file: %s", err)
			continue
		}

		hashes[i] = sha256.Sum256(data)
	}

	ticker := time.Tick(duration)
	for {
		<-ticker

		change := false
		for i, file := range files {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				logger.Printf("error watching file: %s", err)
				continue
			}

			newHash := sha256.Sum256(data)
			if !bytes.Equal(hashes[i][:], newHash[:]) {
				// Detected change
				logger.Printf("detected change on %s, reloading", file)
				change = true
				hashes[i] = newHash
			}
		}

		if change {
			notify <- true
		}
	}
}
