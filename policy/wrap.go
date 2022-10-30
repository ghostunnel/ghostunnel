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

	"github.com/open-policy-agent/opa/rego"
)

type wrappedPolicy struct {
	wrapped *rego.PreparedEvalQuery
}

// WrapForTest creates a policy from a pepared query, useful for testing.
// Do not use this in code -- the policy will not be able to reload.
func WrapForTest(query *rego.PreparedEvalQuery) Policy {
	return &wrappedPolicy{query}
}

// Reload transparently reloads the certificate.
func (w *wrappedPolicy) Reload() error {
	return nil
}

// Eval runs the underlying policy.
func (w *wrappedPolicy) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return w.wrapped.Eval(ctx, options...)
}
