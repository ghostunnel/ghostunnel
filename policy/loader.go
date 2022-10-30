/*-
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

package policy

import (
	"context"
	"sync/atomic"
	"unsafe"

	"github.com/open-policy-agent/opa/rego"
)

type filePolicy struct {
	// Path to policy file
	policyPath string

	// Query to run on eval
	policyQuery string

	// Cached *rego.PreparedEvalQuery
	cachedPolicy unsafe.Pointer
}

// LoadFromFile creates a reloadable policy from a rego file.
func LoadFromFile(policyPath, policyQuery string) (Policy, error) {
	p := filePolicy{
		policyPath:  policyPath,
		policyQuery: policyQuery,
	}
	err := p.Reload()
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Reload transparently reloads the policy.
func (p *filePolicy) Reload() error {
	peq, err := rego.New(
		rego.Query(p.policyQuery),
		rego.Load([]string{p.policyPath}, nil),
	).PrepareForEval(context.Background())
	if err != nil {
		return err
	}

	atomic.StorePointer(&p.cachedPolicy, unsafe.Pointer(&peq))
	return nil
}

// Eval runs the underlying policy.
func (p *filePolicy) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	peq := (*rego.PreparedEvalQuery)(atomic.LoadPointer(&p.cachedPolicy))
	return peq.Eval(ctx, options...)
}
