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
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"

	netproxy "golang.org/x/net/proxy"
)

// Dialer connects to a target selected from an SRV record set. It implements
// netproxy.ContextDialer so it can be composed with other dialers (e.g.
// certloader.DialerWithCertificate). The network and address arguments to
// DialContext are ignored; the SRV name configured at construction time
// determines the lookup, and resolved targets are dialed over TCP via base.
type Dialer struct {
	name string
	base netproxy.ContextDialer
}

// NewDialer returns a Dialer that resolves the SRV name on each connection
// and tries the resulting targets in priority/weight order. The name is
// queried directly (no _service._proto prefix is added), so callers should
// pass a fully-qualified SRV name like "_https._tcp.example.com".
func NewDialer(name string, base netproxy.ContextDialer) (*Dialer, error) {
	if name == "" {
		return nil, errors.New("SRV name must not be empty")
	}
	if base == nil {
		return nil, errors.New("base dialer must not be nil")
	}
	return &Dialer{name: name, base: base}, nil
}

// DialContext resolves the configured SRV name and dials the resulting
// targets in priority/weight order. The network and address arguments
// are ignored.
func (d *Dialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", d.name)
	if err != nil {
		return nil, fmt.Errorf("SRV lookup for %s failed: %w", d.name, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no SRV records for %s", d.name)
	}

	sortSRV(records, rand.IntN)

	var errs []error
	for _, rec := range records {
		addr := net.JoinHostPort(rec.Target, strconv.Itoa(int(rec.Port)))
		conn, err := d.base.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", addr, err))
	}
	return nil, fmt.Errorf("all SRV targets unreachable for %s: %w", d.name, errors.Join(errs...))
}
