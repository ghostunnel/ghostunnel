# Plan: bind TLS session resumption to config reloads

Target branch: `next` (as of `a81d7b1`). All line references are against that
commit.

## Goal

Make the intended resumption behavior explicit in code, enforced for every
certificate source, documented, and covered by tests:

1. **Within a reload generation**, a resumed TLS session reuses the access
   decision made during the original full handshake. The ACL (`--allow-*`,
   `--allow-policy`) is not re-evaluated. This is the performance point of
   resumption and stays as is.
2. **Every reload** (signal or `--timed-reload`) invalidates all outstanding
   sessions. The next connection from every client is a full handshake
   evaluated against the reloaded certificate, CA bundle and policy.

## Background

- The server ACL runs in `tls.Config.VerifyPeerCertificate`
  (`main.go:926`). The client-mode equivalent is at `main.go:1188`.
- Go does not call `VerifyPeerCertificate` on resumed connections.
  `VerifyConnection` does run on resumptions.
- On resumption Go still checks these things (Go 1.27, `checkForResumption`
  in `handshake_server.go` and `handshake_server_tls13.go`):
  - The ticket is younger than `maxSessionTicketLifetime`, which is 7 days.
    TLS 1.3 issues a fresh ticket on each resumption, so the window rolls
    forward.
  - The client leaf certificate in the ticket has not passed `NotAfter`.
  - The stored chain still verifies against the current `ClientCAs`. This
    only applies when `ClientAuth >= VerifyClientCertIfGiven`, so it is
    skipped under `RequireAnyClientCert` (SPKI pin mode and SPIFFE Workload
    API).
- Go's automatic ticket keys are per `tls.Config` object. They rotate every
  24h and are kept for 7 days. `Config.Clone()` copies them from the source
  config, and a config that has never served a handshake has none.

## Current behavior on `next`

### How invalidation works today (implicit)

1. `env.reload()` (`signals.go:115`) calls `tlsConfigSource.Reload()`, then
   `regoPolicy.Reload()`.
2. The file, PKCS#11 and keychain sources call `LoadTrustStore()`, which
   allocates a new `*x509.CertPool` every time, even if the file is
   unchanged (`keystore.go:94`, `pkcs11_enabled.go:112`,
   `certstore_enabled.go:185`). The ACME source does the same in its
   `Reload()` (`acmetlsconfig.go:208`).
3. `certTLSConfig.GetServerConfig()` (`certtlsconfig.go:100`) and
   `acmeTLSConfig.GetServerConfig()` (`acmetlsconfig.go:262`) cache the built
   config keyed on the pool pointer. The new pointer forces a rebuild from
   `base.Clone()`, which has no ticket keys.
4. `Listener.Accept()` (`listener.go:43`) fetches the config per connection.
   New connections get the rebuilt config and new ticket keys. Old tickets no
   longer decrypt, so the client falls back to a full handshake.

This was checked live against a `next` build with `--cert/--key/--cacert` and
`--allow-policy`:

| Step | TLS 1.3 | TLS 1.2 |
|---|---|---|
| Second connection, shared session cache, no reload | resumed, admitted | resumed, admitted |
| After SIGHUP with policy changed allow → deny, reusing old session | full handshake, denied | handshake rejected |
| After SIGHUP with policy unchanged (allow), reusing old session | full handshake, admitted | not run |

The last row shows that any reload drops resumption, whether or not the policy
changed.

### Gaps

These gaps come from reading the code. They were not reproduced live. The
tests below are written to confirm them before the fix and guard them after.

1. **SPIFFE Workload API never invalidates.** `spiffeTLSConfigSource.Reload()`
   is a no-op (`spiffe_tls_config.go:58`), and the server config is built once
   and cached forever (`:108`, `:143`). Ticket keys never rotate on reload.
   With `RequireAnyClientCert` there is no chain re-check on resumption
   either. A resumed session keeps its original SPIFFE and OPA decision until
   the ticket or client SVID expires. The practical bound is the client SVID's
   `NotAfter`, and SPIRE's default X.509-SVID TTL is 1h.
2. **TLS source reload fails, policy reload succeeds.** Examples: a CA bundle
   that is briefly unreadable, or a cert file that is only partly written.
   `Reload()` keeps the old pool, so the pointer is unchanged and nothing is
   rebuilt. Tickets from before the reload keep resuming under the new policy
   until the next successful TLS reload.
3. **Ordering window inside a reload.** The TLS source reloads first
   (`signals.go:117`), then the policy (`signals.go:121`). A connection
   accepted after the pool swap gets the new config and new keys. If its ACL
   runs before the policy pointer is swapped, it is evaluated under the old
   policy. Its ticket is minted under the new keys and stays valid after the
   swap. The window is as long as the policy takes to load and compile.
4. **None of this is stated or tested.** No unit or integration test uses
   resumption. The churn benchmark turns the client session cache off on
   purpose (`proxy/churn_bench_test.go`). The only docs that mention
   resumption are for the ACME challenge config (`docs/certificates/acme.md:82`).

### Not affected

- **Client mode.** No `ClientSessionCache` is set, so connections never
  resume and `VerifyPeerCertificateClient` runs on every connection.
- **ACME `acme-tls/1` relaxed config.** Session tickets are disabled
  (`acmetlsconfig.go:319`).
- **Status listener.** It uses `NoClientCert` and has no ACL.

## Design

Every server-side session is bound to a **reload generation**.

### New certloader types (`certloader/session_generation.go`)

Names are placeholders.

```go
// SessionGeneration is incremented on every reload. Server-side TLS sessions
// created in one generation cannot be resumed in another.
type SessionGeneration struct{ n atomic.Uint64 }

func (g *SessionGeneration) Advance()        { g.n.Add(1) }
func (g *SessionGeneration) Current() uint64 { return g.n.Load() }

// BindSessionsToGeneration wraps a TLSServerConfig so that resumption only
// succeeds within the generation that created the session.
func BindSessionsToGeneration(inner TLSServerConfig, gen *SessionGeneration) TLSServerConfig
```

The wrapper's `GetServerConfig()` behaves as follows:

- It reads `inner.GetServerConfig()` and `gen.Current()`. If both match the
  cached pair, it returns the cached config. This keeps the shared-config fast
  path, with no clone per connection.
- Otherwise it clones the inner config, installs session hooks, and caches the
  result with `atomic.Pointer`. Two callers racing a change may each build
  once, which is harmless. `certTLSConfig` already accepts the same trade-off.
- Session hooks on the clone use the generation `g` that was captured when the
  clone was built:
  - `WrapSession` appends a tag to `ss.Extra`, then calls
    `cfg.EncryptTicket`. The tag is a fixed prefix plus the 8-byte big-endian
    generation. Go requires entries in `SessionState.Extra` to be
    append-only and self-identifying.
  - `UnwrapSession` calls `cfg.DecryptTicket`. It returns `(nil, nil)` unless
    the tag for `g` is present. Go then does a full handshake instead of
    failing.

There are two layers on purpose:

- **A fresh clone per generation** gets its own automatic ticket keys. Go's
  24h key rotation and 7-day retention are kept.
- **The explicit tag** means correctness does not depend on the clones having
  separate keys. For example, if the inner config ever serves handshakes
  directly and populates keys that clones then inherit, the tag still forces
  a full handshake.

The generation is captured when the clone is built, not read when a ticket is
wrapped. A handshake that straddles a reload therefore cannot mint a ticket
for the new generation from a decision made under the old one.

### Reload path (`signals.go`)

`env.reload()` calls `env.sessionGeneration.Advance()` after both
`tlsConfigSource.Reload()` and `regoPolicy.Reload()`. It does this even when
either reload returns an error, and before `env.status.Listening()`. The
effects:

- **Gap 2 is closed.** Invalidation no longer depends on the trust store
  pointer changing.
- **Gap 3 is closed.**
  - The policy swap happens before the advance.
  - A connection picks up its config at `Accept`.
  - So any connection on the new generation evaluated its ACL under the
    reloaded policy. Any ticket from the old generation is rejected.
- **Tests and operators can rely on the status endpoint.** Once it reads
  `listening`, the new generation is in effect.

Add a comment on `reload()` that states the ordering requirement.

### Wiring (`main.go`)

- Add `sessionGeneration *certloader.SessionGeneration` to `Environment`
  (`main.go:215`). Initialize it for both server and client mode. Client mode
  advances it harmlessly and never reads it.
- In `serverListen`, wrap before building the listener (`main.go:934-941`):
  `serverConfig = certloader.BindSessionsToGeneration(serverConfig, env.sessionGeneration)`.
  This applies to every source, including the SPIFFE Workload API, which
  closes gap 1.
- Do not wrap the status listener (`main.go:1099-1111`). It has no client
  auth, and in ACME mode `WithoutACMEChallenge` clones on every call, which
  would defeat the wrapper's cache.

### Performance

- Within a generation, resumption behaves exactly as it does today and skips
  the ACL and OPA.
- Cost per reload: one `Clone()`.
- Cost per accepted connection: one atomic load and a pointer comparison.
- Resumption is dropped once per reload. File sources already behave this way
  today.

### Requirements on the inner config

- `inner.GetServerConfig()` must return the same pointer until something
  changes. This holds for `certTLSConfig`, `acmeTLSConfig` and
  `spiffeTLSConfig`. Document it on the wrapper and test it.
- Generation configs must not be cloned again. `WrapSession` and
  `UnwrapSession` close over the original clone's keys. Document this.
- The ACME `GetConfigForClient` hook clones the *inner* config and disables
  tickets, so validator handshakes are unaffected. Test it.

### Alternatives rejected

| Option | Why not |
|---|---|
| Run the ACL in `VerifyConnection` | Runs OPA on every resumption, which removes the benefit of resuming. |
| `SessionTicketsDisabled = true` | Removes resumption entirely. |
| `SetSessionTicketKeys` with a new key on each reload | Turns off Go's automatic 24h key rotation. With rare reloads, keys would never rotate. |
| Keep the implicit rebuild and only fix the SPIFFE cache | Leaves gaps 2 and 3, and still depends on pool pointer identity. |

## Code changes

| File | Change |
|---|---|
| `certloader/session_generation.go` (new) | `SessionGeneration`, `BindSessionsToGeneration`, tag encode and match helpers. |
| `certloader/tlsconfig.go` | Doc comment on `TLSServerConfig`: returned configs must be stable pointers between changes. |
| `signals.go` | Advance the generation at the end of `reload()`, with a comment on ordering. |
| `main.go` | Add the `Environment` field and initialize it. Wrap in `serverListen`. Add comments with lint suppressions at `:926` and `:1188` (see Lint). |
| `certloader/spiffe_tls_config.go` | Replace the "build once, cache forever" comment so it points to the generation wrapper for session invalidation. Add lint suppressions at `:132` and `:168`. |
| `.golangci.yml` | Enable `gosec` limited to G123 (see Lint). |
| `tests/common.py` | Session reuse support in `TlsClient` (see Integration tests). |

## Tests

### Unit: `certloader/session_generation_test.go` (new)

All tests use real loopback TLS with a `tls.NewLRUClientSessionCache`. They
assert on `ConnectionState().DidResume` and on a counting
`VerifyPeerCertificate`. Run TLS 1.2 and TLS 1.3 as subtests.

1. `ResumesWithinGeneration`: the second connection resumes and the verify
   counter does not increase. This pins resumption as a performance feature.
2. `InvalidatesOnAdvance`: after `Advance()`, the client's cached session
   gives a full handshake and the verify counter increases.
3. `RejectsOtherGenerationWithSharedKeys`: set `SetSessionTicketKeys` on the
   inner config so every clone inherits the same keys. A ticket from
   generation N must still give a full handshake in generation N+1. This
   proves the tag check alone is enough.
4. `ConfigStableWithinGeneration`: same pointer on repeated calls. New
   pointer after `Advance()`. New pointer when the inner config pointer
   changes, as happens on a trust store reload.
5. `DenyAfterAdvance`: the verify callback switches from allow to deny,
   followed by `Advance()`. The resuming client is rejected.
6. `PreservesACMEChallengeHook`: wrap an ACME server config. `GetConfigForClient`
   for a validator-shaped ClientHello still returns a config with
   `SessionTicketsDisabled`. A normal ClientHello returns nil.

### Unit: `certloader/spiffe_tls_config_test.go`

7. `TestWorkloadAPISessionInvalidatedOnAdvance`: use the fake Workload API
   (`certloader/internal/test`). Resumption works within a generation and
   gives a full handshake after `Advance()`. On current `next` there is no
   wrapper, so this is gap 1.

### Unit: `signals_test.go` (new, no build tag; calls `env.reload()` directly)

8. `TestReloadAdvancesGenerationAfterPolicy`: a fake `policy.Policy` records
   `Current()` during its `Reload()`. It must see the old value, and the value
   afterwards must be old+1. This covers gap 3's ordering.
9. `TestReloadAdvancesGenerationWhenTLSReloadFails`: the fake source's
   `Reload()` returns an error and the generation still advances. This covers
   gap 2.
10. `TestReloadAdvancesGenerationWhenPolicyReloadFails`.
11. `TestReloadAdvancesBeforeListening`: the generation has advanced by the
    time status reads `listening`.

Existing fakes to build on: `countingTLSConfigSource` (`unix_test.go:61`, which
is `!windows` only, so move or copy it) and `failingTLSConfigSource`
(`main_test.go:800`).

### Unit: `main_test.go`

12. `TestClientConfigHasNoSessionCache`: the client-mode `tls.Config` has a nil
    `ClientSessionCache`. If a client session cache is ever added, this forces
    a decision about skipping `VerifyPeerCertificateClient` on resumption.

### Integration: `tests/common.py`

- `TlsClient` accepts an optional shared `ssl.SSLContext` and a `session`, and
  exposes `session` and `session_reused`. Python only accepts a session on a
  socket from the same context.
- Add a helper that waits for a reload to finish: `last_reload` has changed
  **and** `message == 'listening'`. `last_reload` alone is not enough because
  it is stamped at the start of the reload (`status.go:129`).
- For TLS 1.3, exchange data before reading `.session`. The ticket arrives
  after the handshake.

### Integration: `tests/test-server-opa-reload-resumption.py` (new)

Uses existing bundles only:

- `test-allow-all-policy.tar.gz` allows every client.
- `test-server-allow-opa-policy.tar.gz` allows DNS SAN `client1` only.

Steps:

1. Create certs `server`, `client1` and `client2`. Copy the allow-all bundle
   into a temp dir.
2. Start the server with `--allow-policy`, `--allow-query=data.policy.allow`,
   `--status` and `reload_args()`.
3. For each of TLS 1.2 and TLS 1.3, `client2` connects and exchanges data.
   Save the session. Reconnect with it and assert `session_reused`. This pins
   the performance behavior.
4. Swap in the `client1`-only bundle, trigger a reload, and wait for it to
   finish.
5. For each version, `client2` reconnects with the saved session and must be
   rejected. For TLS 1.3 that means a server close or alert after the
   client-side handshake.
6. `client1` with a fresh context is admitted.

This passes on current `next` for file sources. It is a regression guard.

### Integration: `tests/test-server-opa-reload-resumption-ca-failure.py` (new)

Same as above, but `--cacert` points at a temp copy of the CA bundle. Before
reloading, overwrite that copy with invalid PEM and swap the policy. The
reload logs `error reloading TLS configuration`, and `client2` with its saved
session must still be rejected. Then restore the CA, reload, and check that
`client1` still works.

This is expected to **fail on current `next`** (gap 2) and pass after the
change.

### Windows

`trigger_reload()` on Windows relies on `--timed-reload=1s`, so the generation
advances every second. Step 3's "resumes without reload" check would be
flaky. Run it on non-Windows only (`IS_WINDOWS` guard), and keep the
invalidation checks on all platforms.

## Documentation

- **`docs/certificates/reloading.md`**: add a section "TLS Session
  Resumption" after "What Gets Reloaded". Proposed text:
  > Ghostunnel supports TLS session resumption. A resumed connection reuses
  > the access control decision from the client's original full handshake;
  > `--allow-*` flags and `--allow-policy` are not re-evaluated on resumption.
  > Every reload, whether triggered by signal or `--timed-reload`, and whether
  > or not it succeeds, invalidates all existing sessions. The next connection
  > from each client performs a full handshake against the reloaded
  > certificate, CA bundle and policy. Frequent `--timed-reload` intervals
  > therefore reduce the benefit of resumption. Resumption is also refused
  > once the client certificate has expired.
- **`docs/certificates/reloading.md`, "Source-Specific Behavior"**
  (SPIFFE bullet): the SVID and bundle rotations the provider pushes apply to
  new full handshakes. Resumed sessions keep their original decision until the
  next reload or until the client SVID expires.
- **`docs/certificates/spiffe-workload-api.md`, "Trust Bundle Updates"**
  (`:87`): the same note. A reload (SIGHUP or `--timed-reload`) is what
  invalidates sessions, even though no reload is needed to pick up new
  credentials.
- **`docs/security/access-flags.md`** (`:210`, OPA paragraph): after "Policy
  bundles reload at runtime...", add that policies are evaluated during full
  handshakes and that a reload invalidates resumed sessions. Link to the
  reloading page.
- **`docs/networking/timeouts.md`**, lifecycle step 1 "Establishment": one
  sentence saying the handshake may be a resumption, and link to the
  reloading page.

## Lint

- gosec `v2.28.0` (pulled in by golangci-lint `v2.13.1`) includes G123. It
  flags any `tls.Config` that sets `VerifyPeerCertificate` without setting
  `VerifyConnection` or `SessionTicketsDisabled`. It does not recognize
  `WrapSession` or `UnwrapSession`.
- A trial run on `next` with only G123 enabled reported:
  - Production sites: `main.go:926`, `main.go:1188`,
    `certloader/spiffe_tls_config.go:132`, `certloader/spiffe_tls_config.go:168`.
  - Tests: `auth/doc_test.go:39` and `:61`, and
    `certloader/spiffe_tls_config_test.go:52`, `:83` and `:91`.
- The default `max-same-issues: 3` hides everything past the third
  identical message. Lint still fails, but output is truncated. Run with
  `--max-same-issues 0` when triaging.
- Config: add `gosec` to `linters.enable` with
  `settings.gosec.includes: [G123]`. Add an exclusion rule for `gosec` on
  `_test\.go`, matching the existing errcheck and forbidigo pattern.
- Suppress each production site with a reason. This makes the intended
  behavior visible where a reader will look for it:
  - `main.go:926`: `//nolint:gosec // G123: intentional; resumed sessions reuse the full-handshake ACL decision and are invalidated on every reload by certloader.BindSessionsToGeneration`
  - `main.go:1188` and `spiffe_tls_config.go:132`: `//nolint:gosec // G123: client config sets no ClientSessionCache, so sessions never resume`
  - `spiffe_tls_config.go:168`: the same as `main.go:926`.
- This way, any new `tls.Config` that sets `VerifyPeerCertificate` elsewhere
  fails lint until someone decides how resumption should behave for it.

## Verification

```bash
export PATH=/usr/local/go<VERSION>/bin:$PATH     # per CLAUDE.md
go test ./certloader/ -run 'SessionGeneration|WorkloadAPISession' -v
go test . -run 'TestReload|TestClientConfigHasNoSessionCache' -v
go tool mage test:keys
go tool mage test:single test-server-opa-reload-resumption
go tool mage test:single test-server-opa-reload-resumption-ca-failure
go tool mage go:lint
go tool mage test:all
```

Before implementing, run the new tests against unchanged `next` and record
which ones fail. Expected failures:

- Test 7 (gap 1).
- Tests 8–11, because the generation does not exist yet.
- The CA-failure integration test (gap 2).

Everything else should pass before and after.

## Commit sequence (local until reviewed)

1. certloader: add `SessionGeneration` and `BindSessionsToGeneration` with
   unit tests 1–7.
2. main: advance the generation on reload and wrap the tunnel listener
   config, with tests 8–12.
3. tests: session reuse helpers and the two integration tests.
4. docs: document session resumption and reload invalidation.
5. lint: enable gosec G123 and annotate the intended sites.

Each commit must pass `go fmt`, `go tool mage go:lint` and
`go tool mage test:unit`. Run `go tool mage test:all` before pushing.

## Open questions

- **SPIFFE bundle updates.** Should a trust bundle update pushed by the
  Workload API also advance the generation? `X509Source.Updated()` exists,
  but it also fires on every SVID rotation, so sessions would be dropped
  every rotation. Advancing only on a real bundle change would need a
  comparison, because `X509Source` cannot list its bundles. Proposed: out of
  scope, documented as above.
- **No-op reloads.** Should we skip advancing when nothing changed? That would
  need content hashes of the certificate, CA bundle and policy. It would keep
  resumption across no-op `--timed-reload` ticks. Proposed: out of scope. The
  simpler rule of "every reload invalidates" is easier to reason about.
- **`auth/doc_test.go` examples.** These show users how to wire
  `VerifyPeerCertificate`. Should they mention resumption?
