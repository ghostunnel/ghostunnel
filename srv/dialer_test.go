/*-
 * Copyright 2025 Square Inc.
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
	"time"
)

func TestBuildSRVDialer_InvalidParameters(t *testing.T) {
	_, err := BuildSRVDialer("", "_tcp", "example.com", nil, time.Second)
	if err == nil {
		t.Error("expected error for empty service")
	}

	_, err = BuildSRVDialer("_https", "", "example.com", nil, time.Second)
	if err == nil {
		t.Error("expected error for empty proto")
	}

	_, err = BuildSRVDialer("_https", "_tcp", "", nil, time.Second)
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestFilterFailedTargets(t *testing.T) {
	records := []*net.SRV{
		{Target: "target1.example.com", Port: 443},
		{Target: "target2.example.com", Port: 443},
		{Target: "target3.example.com", Port: 443},
	}

	failed := map[string]bool{
		"target2.example.com:443": true,
	}

	available := filterFailedTargets(records, failed)

	if len(available) != 2 {
		t.Errorf("expected 2 available targets, got %d", len(available))
	}

	for _, record := range available {
		if record.Target == "target2.example.com" {
			t.Error("failed target should not be in available list")
		}
	}
}

// Note: Full integration tests for BuildSRVDialer would require:
// 1. Mock DNS resolver (complex to set up)
// 2. Test network connections (requires test infrastructure)
// These tests are left as integration tests that can be run with real DNS
// or in a test environment with mocked DNS.
