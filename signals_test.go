/*-
 * Copyright 2026 Ghostunnel
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

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ghostunnel/ghostunnel/certloader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for reload()'s contract around the session generation. The generation
// is what stops a client from resuming into an access decision that predates
// the reload, so when it advances relative to the rest of the reload is a
// correctness property, not an implementation detail.

// countingTLSConfigSource extends the failingTLSConfigSource with a counter
// for tracking Reload() invocations.
type countingTLSConfigSource struct {
	failingTLSConfigSource
	reloadCalls atomic.Int32
}

func (c *countingTLSConfigSource) Reload() error {
	c.reloadCalls.Add(1)
	return nil
}

// reloadErrorTLSConfigSource fails every reload, standing in for a CA bundle
// that is briefly unreadable or a certificate file caught halfway through
// being written.
type reloadErrorTLSConfigSource struct {
	failingTLSConfigSource
}

func (c *reloadErrorTLSConfigSource) Reload() error {
	return errors.New("test error: Reload failed")
}

// recordingPolicy records what it could observe about the reload while its own
// Reload was running.
type recordingPolicy struct {
	env *Environment
	err error

	reloads          int
	generationDuring uint64
	statusDuring     string
}

func (p *recordingPolicy) Reload() error {
	p.reloads++
	p.generationDuring = p.env.sessionGeneration.Current()
	p.statusDuring = p.env.status.status(context.Background()).Message
	return p.err
}

func (p *recordingPolicy) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return nil, errors.New("test error: Eval not implemented")
}

// newReloadTestEnvironment returns an Environment wired up just enough to call
// reload() directly.
func newReloadTestEnvironment(source certloader.TLSConfigSource) *Environment {
	return &Environment{
		status:          newStatusHandler(dummyDial, "test", "127.0.0.1:0", "127.0.0.1:0", ""),
		tlsConfigSource: source,
	}
}

// The policy is swapped in before the generation advances, so a connection on
// the new generation was necessarily evaluated against the reloaded policy.
// Were it the other way around, a connection accepted after the advance could
// be admitted by the old policy and then hold a ticket that stays valid.
func TestReloadAdvancesGenerationAfterPolicy(t *testing.T) {
	source := &countingTLSConfigSource{}
	env := newReloadTestEnvironment(source)
	policy := &recordingPolicy{env: env}
	env.regoPolicy = policy

	before := env.sessionGeneration.Current()
	env.reload()

	require.Equal(t, 1, policy.reloads, "the policy should have been reloaded")
	assert.Equal(t, before, policy.generationDuring,
		"the generation must not advance until the policy has been swapped in")
	assert.Equal(t, before+1, env.sessionGeneration.Current(),
		"the generation must advance once the reload is done")
	assert.EqualValues(t, 1, source.reloadCalls.Load())
}

// A failed TLS reload leaves the old certificate and trust store in place,
// which is deliberate. It must not also leave old sessions resumable: the
// policy may have reloaded even though the certificate source did not, and a
// client holding a ticket would otherwise keep the decision it was granted
// under the previous one.
func TestReloadAdvancesGenerationWhenTLSReloadFails(t *testing.T) {
	env := newReloadTestEnvironment(&reloadErrorTLSConfigSource{})
	policy := &recordingPolicy{env: env}
	env.regoPolicy = policy

	before := env.sessionGeneration.Current()
	env.reload()

	require.Equal(t, 1, policy.reloads, "a failed TLS reload must not skip the policy reload")
	assert.Equal(t, before+1, env.sessionGeneration.Current(),
		"the generation must advance even when the TLS reload fails")
}

// Same the other way around: the policy failing to reload leaves the old
// policy in place, but the certificate and trust store may have changed, so
// outstanding sessions still have to go.
func TestReloadAdvancesGenerationWhenPolicyReloadFails(t *testing.T) {
	env := newReloadTestEnvironment(&countingTLSConfigSource{})
	policy := &recordingPolicy{env: env, err: errors.New("test error: policy reload failed")}
	env.regoPolicy = policy

	before := env.sessionGeneration.Current()
	env.reload()

	require.Equal(t, 1, policy.reloads)
	assert.Equal(t, before+1, env.sessionGeneration.Current(),
		"the generation must advance even when the policy reload fails")
}

// A reload with no policy configured still advances the generation: the
// certificate and trust store are reason enough.
func TestReloadAdvancesGenerationWithoutPolicy(t *testing.T) {
	env := newReloadTestEnvironment(&countingTLSConfigSource{})

	before := env.sessionGeneration.Current()
	env.reload()

	assert.Equal(t, before+1, env.sessionGeneration.Current())
}

// The generation advances before the status goes back to listening, so a
// listening status can be read as "the new generation is in effect". The
// integration tests rely on this to know when it is safe to check that an old
// session no longer resumes.
func TestReloadAdvancesBeforeListening(t *testing.T) {
	env := newReloadTestEnvironment(&countingTLSConfigSource{})
	policy := &recordingPolicy{env: env}
	env.regoPolicy = policy
	env.status.Listening()

	before := env.sessionGeneration.Current()
	env.reload()

	assert.Equal(t, "reloading", policy.statusDuring,
		"the status must still report reloading while the reload is in flight")
	assert.Equal(t, before, policy.generationDuring)
	assert.Equal(t, "listening", env.status.status(context.Background()).Message)
	assert.Equal(t, before+1, env.sessionGeneration.Current(),
		"the generation must have advanced by the time the status reads listening")
}
