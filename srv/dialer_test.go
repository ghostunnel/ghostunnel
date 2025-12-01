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

package srv

import (
	"net"
	"testing"
)

func TestNewDialer_EmptyName(t *testing.T) {
	if _, err := NewDialer("", &net.Dialer{}); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestNewDialer_NilBase(t *testing.T) {
	if _, err := NewDialer("_https._tcp.example.com", nil); err == nil {
		t.Error("expected error for nil base dialer")
	}
}
