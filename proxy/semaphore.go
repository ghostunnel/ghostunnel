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
)

type semaphore interface {
	Acquire(ctx context.Context, n int64) error
	Release(n int64)
}

type unlimitedSemaphore struct{}

func (u *unlimitedSemaphore) Acquire(ctx context.Context, n int64) error {
	return ctx.Err()
}

func (u *unlimitedSemaphore) Release(n int64) {}
