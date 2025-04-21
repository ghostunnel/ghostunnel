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
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

type filePolicy struct {
	// Path to policy file
	policyPath string

	// Query to run on eval
	policyQuery string

	// Cached *rego.PreparedEvalQuery
	cachedPolicy unsafe.Pointer
}

// LoadFromPath creates a reloadable policy from a rego file.
func LoadFromPath(policyPath, policyQuery string) (Policy, error) {
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
	var peq rego.PreparedEvalQuery
	var err error
	if strings.HasSuffix(p.policyPath, ".rego") {
		// For backwards compatibility with old versions of Ghostunnel,
		// we load Rego files as v0 policies. This may change in the future.
		peq, err = rego.New(
			rego.Query(p.policyQuery),
			rego.Load([]string{p.policyPath}, nil),
			rego.SetRegoVersion(ast.RegoV0),
		).PrepareForEval(context.Background())
	} else {
		// In newer version of Ghostunnel, we recommend loading policies
		// via a bundle. This allows bundling data and policy files as well
		// specifying the Rego version (v0 or v1) in the bundle manifest.
		peq, err = rego.New(
			rego.Query(p.policyQuery),
			rego.LoadBundle(p.policyPath),
		).PrepareForEval(context.Background())
	}
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
