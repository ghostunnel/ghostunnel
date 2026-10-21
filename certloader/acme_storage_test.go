/*-
 * Copyright 2026 Ghostunnel
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

package certloader

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// TestMain points certmagic at in-memory storage so ACME tests neither touch
// the user's home directory nor share lock files with each other. certmagic's
// file locks are kept open by a refresher goroutine; on Windows that blocks
// unlocking, and later tests then hang waiting on the stale lock.
func TestMain(m *testing.M) {
	certmagic.Default.Storage = newMemStorage()
	os.Exit(m.Run())
}

// memStorage is a minimal in-memory certmagic.Storage for tests.
type memStorage struct {
	mu    sync.Mutex
	data  map[string]memEntry
	locks map[string]chan struct{}
}

type memEntry struct {
	value    []byte
	modified time.Time
}

func newMemStorage() *memStorage {
	return &memStorage{
		data:  make(map[string]memEntry),
		locks: make(map[string]chan struct{}),
	}
}

func (s *memStorage) Lock(ctx context.Context, name string) error {
	for {
		s.mu.Lock()
		held, ok := s.locks[name]
		if !ok {
			s.locks[name] = make(chan struct{})
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		select {
		case <-held:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *memStorage) Unlock(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if held, ok := s.locks[name]; ok {
		close(held)
		delete(s.locks, name)
	}
	return nil
}

func (s *memStorage) Store(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = memEntry{value: append([]byte(nil), value...), modified: time.Now()}
	return nil
}

func (s *memStorage) Load(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), e.value...), nil
}

func (s *memStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for k := range s.data {
		if k == key || strings.HasPrefix(k, key+"/") {
			delete(s.data, k)
			found = true
		}
	}
	if !found {
		return fs.ErrNotExist
	}
	return nil
}

func (s *memStorage) Exists(_ context.Context, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[key]; ok {
		return true
	}
	for k := range s.data {
		if strings.HasPrefix(k, key+"/") {
			return true
		}
	}
	return false
}

func (s *memStorage) List(_ context.Context, prefix string, recursive bool) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]bool)
	var keys []string
	for k := range s.data {
		if !strings.HasPrefix(k, prefix+"/") {
			continue
		}
		key := k
		if !recursive {
			rest := strings.TrimPrefix(k, prefix+"/")
			key = prefix + "/" + strings.SplitN(rest, "/", 2)[0]
		}
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, fs.ErrNotExist
	}
	return keys, nil
}

func (s *memStorage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[key]; ok {
		return certmagic.KeyInfo{Key: key, Modified: e.modified, Size: int64(len(e.value)), IsTerminal: true}, nil
	}
	for k := range s.data {
		if strings.HasPrefix(k, key+"/") {
			return certmagic.KeyInfo{Key: key, IsTerminal: false}, nil
		}
	}
	return certmagic.KeyInfo{}, fs.ErrNotExist
}
