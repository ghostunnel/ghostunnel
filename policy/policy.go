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

	"github.com/open-policy-agent/opa/v1/rego"
)

// Policy wraps a OPA policy and supports reloading at runtime.
type Policy interface {
	// Reload will reload the policy. Subsequent calls to Evaluate will run
	// the newly loaded policy, if reloading was successful. If reloading fails,
	// the old state is kept.
	Reload() error

	// Evaluate the underlying policy. See rego docs for more info.
	Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error)
}
