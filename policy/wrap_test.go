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
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
)

func TestStaticPolicy(t *testing.T) {
	ctx := context.Background()
	query := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("allow.rego", allowAllPolicy),
	)

	prepped, err := query.PrepareForEval(ctx)
	if err != nil {
		t.Fatal(err)
	}

	policy := WrapForTest(&prepped)
	assert.Nil(t, policy.Reload())

	res, err := policy.Eval(ctx, rego.EvalInput(map[string]any{}))
	assert.Nil(t, err)
	assert.True(t, res.Allowed())
}
