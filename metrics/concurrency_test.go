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

package metrics

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Concurrency tests for the pieces that exist purely for concurrent use.
// These have real value under -race (see the test:race mage target).

// TestTimerConcurrentObserve hammers observeNanos from many goroutines. The
// min/max CAS loops must converge on the true extremes and the summary count
// must reflect every observation.
func TestTimerConcurrentObserve(t *testing.T) {
	r := NewRegistry("test")
	tm := r.registerTimer("conn.handshake")

	const goroutines = 8
	const perGoroutine = 1000

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				// Values span [1, goroutines*perGoroutine], each observed once.
				tm.observeNanos(int64(g*perGoroutine + i + 1))
			}
		}(g)
	}
	wg.Wait()

	assert.Equal(t, int64(1), tm.minNs.Load(), "min must be the smallest observation")
	assert.Equal(t, int64(goroutines*perGoroutine), tm.maxNs.Load(), "max must be the largest observation")

	count, ok := r.TimerCount("conn.handshake")
	require.True(t, ok)
	assert.Equal(t, int64(goroutines*perGoroutine), count, "no observation may be lost")
}

// TestStartRuntimeCollectorConcurrent races StartRuntimeCollector from many
// goroutines. Only one may register the runtime instruments; an unguarded
// second registration would panic in MustRegister.
func TestStartRuntimeCollectorConcurrent(t *testing.T) {
	r := NewRegistry("test")

	const goroutines = 8
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.StartRuntimeCollector(time.Hour)
		}()
	}
	wg.Wait()

	assert.NotNil(t, r.runtime, "the collector must be registered exactly once")
}

// TestConcurrentRegisterAndSnapshot registers instruments while other
// goroutines snapshot the registry, pinning the descriptor-list locking.
// Ghostunnel registers only at startup, but nothing in the API enforces that.
func TestConcurrentRegisterAndSnapshot(t *testing.T) {
	r := NewRegistry("test")

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				r.registerCounter(fmt.Sprintf("reg%d.counter%d", g, i)).Inc(1)
			}
		}(g)
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = r.snapshot()
			}
		}()
	}
	wg.Wait()

	s := r.snapshot()
	assert.Len(t, s.singles, 4*50, "every registered counter must be visible")
}

// TestNewRegistryHostnameFallback verifies an unknowable hostname degrades to
// a placeholder instead of refusing to start.
func TestNewRegistryHostnameFallback(t *testing.T) {
	orig := osHostname
	defer func() { osHostname = orig }()
	osHostname = func() (string, error) { return "", errors.New("no hostname") }

	r := NewRegistry("test")
	assert.Equal(t, "unknown", r.hostname)
}
