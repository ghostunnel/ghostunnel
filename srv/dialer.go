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
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/ghostunnel/ghostunnel/proxy"
	netproxy "golang.org/x/net/proxy"
)

const (
	// maxSRVRetries is the maximum number of connection attempts per dial
	// operation when using SRV records. This prevents infinite loops if all
	// targets are unreachable.
	maxSRVRetries = 10
)

// BuildSRVDialer creates a dialer function that looks up SRV records and
// connects to a selected target. The dialer implements failover by retrying
// with different targets from the SRV record set if a connection fails.
//
// Parameters:
//   - service: The service name (e.g., "_https")
//   - proto: The protocol name (e.g., "_tcp")
//   - name: The domain name (e.g., "example.com")
//   - baseDialer: The underlying dialer to use for connections (can be nil for default)
//   - timeout: Connection timeout duration
//
// Returns a DialFunc that can be used with the proxy package.
func BuildSRVDialer(service, proto, name string, baseDialer netproxy.ContextDialer, timeout time.Duration) (proxy.DialFunc, error) {
	if service == "" || proto == "" || name == "" {
		return nil, fmt.Errorf("service, proto, and name must all be non-empty")
	}

	// Use default dialer if none provided
	if baseDialer == nil {
		baseDialer = &net.Dialer{Timeout: timeout}
	}

	// Create RNG for weighted selection (seed with current time)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	return func(ctx context.Context) (net.Conn, error) {
		// Perform SRV lookup
		_, addrs, err := net.LookupSRV(service, proto, name)
		if err != nil {
			return nil, fmt.Errorf("SRV lookup failed for %s.%s.%s: %w", service, proto, name, err)
		}

		if len(addrs) == 0 {
			return nil, fmt.Errorf("no SRV records found for %s.%s.%s", service, proto, name)
		}

		// Track failed targets to avoid retrying them
		failedTargets := make(map[string]bool)
		var lastErr error

		// Attempt connection with retries
		for attempt := 0; attempt < maxSRVRetries; attempt++ {
			// Filter out failed targets
			available := filterFailedTargets(addrs, failedTargets)
			if len(available) == 0 {
				// All targets in current priority group have failed
				// Try to fall through to next priority group by resetting failed targets
				// and using all records again (SelectSRV will handle priority grouping)
				if attempt == 0 {
					// If this is the first attempt and we filtered everything,
					// something is wrong with our logic
					break
				}
				// Reset and try all records again (will select from next priority)
				failedTargets = make(map[string]bool)
				available = addrs
			}

			// Select a target using priority and weight
			selected, err := SelectSRV(available, rng)
			if err != nil {
				return nil, err
			}

			// Build target address
			targetAddr := fmt.Sprintf("%s:%d", selected.Target, selected.Port)
			targetKey := fmt.Sprintf("%s:%d", selected.Target, selected.Port)

			// Resolve the target hostname to an IP address
			// We need to resolve because the SRV target might be a hostname
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, selected.Target)
			if err != nil {
				// DNS resolution failed for this target, mark as failed and retry
				failedTargets[targetKey] = true
				lastErr = fmt.Errorf("failed to resolve %s: %w", selected.Target, err)
				continue
			}

			if len(ips) == 0 {
				failedTargets[targetKey] = true
				lastErr = fmt.Errorf("no IP addresses found for %s", selected.Target)
				continue
			}

			// Try connecting to the first resolved IP
			// In a production system, you might want to try all IPs, but for
			// simplicity we'll use the first one
			ipAddr := ips[0].IP.String()
			networkAddr := fmt.Sprintf("%s:%d", ipAddr, selected.Port)

			// Attempt connection
			conn, err := baseDialer.DialContext(ctx, "tcp", networkAddr)
			if err != nil {
				// Connection failed, mark target as failed and retry
				failedTargets[targetKey] = true
				lastErr = fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
				continue
			}

			// Success!
			return conn, nil
		}

		// All retries exhausted
		return nil, fmt.Errorf("failed to connect to any SRV target after %d attempts: %w", maxSRVRetries, lastErr)
	}, nil
}

// filterFailedTargets returns a slice of SRV records excluding those that
// have been marked as failed.
func filterFailedTargets(records []*net.SRV, failed map[string]bool) []*net.SRV {
	var available []*net.SRV
	for _, record := range records {
		key := fmt.Sprintf("%s:%d", record.Target, record.Port)
		if !failed[key] {
			available = append(available, record)
		}
	}
	return available
}
