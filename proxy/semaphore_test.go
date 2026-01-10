/*-
 * Copyright 2025 Ghostunnel
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

package proxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnlimitedSemaphoreAcquireWithBackground(t *testing.T) {
	sem := &unlimitedSemaphore{}
	err := sem.Acquire(context.Background(), 1)
	assert.Nil(t, err, "Acquire should return nil for background context")
}

func TestUnlimitedSemaphoreAcquireWithCanceledContext(t *testing.T) {
	sem := &unlimitedSemaphore{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := sem.Acquire(ctx, 1)
	assert.NotNil(t, err, "Acquire should return context error when canceled")
	assert.Equal(t, context.Canceled, err)
}

func TestUnlimitedSemaphoreRelease(t *testing.T) {
	sem := &unlimitedSemaphore{}
	// Should not panic - Release is a no-op for unlimited semaphore
	sem.Release(1)
	sem.Release(100)
	sem.Release(0)
}
