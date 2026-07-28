# Plan: session resumption flag, ticket persistence, and VerifyConnection migration

Target branch: `claude/session-resumption-flag-op181h` (based on `next`).

## Background: current behavior

Session resumption in ghostunnel today is whatever Go's `crypto/tls` defaults
give us; the main proxy path never touches the relevant knobs.

* **Server mode: resumption enabled.** `buildServerConfig` (`tls.go`) never
  sets `SessionTicketsDisabled`, so the server issues TLS 1.2 session tickets
  and TLS 1.3 resumption PSKs. Ticket keys are auto-managed inside the shared
  `tls.Config` cached by the certloader sources.
* **Client mode: resumption disabled.** Go clients only resume when a
  `ClientSessionCache` is set; ghostunnel never sets one, so every backend
  dial is a full handshake.
* **ACME exception.** The TLS-ALPN-01 relaxed handshake sets
  `SessionTicketsDisabled = true` (`certloader/acmetlsconfig.go`) so a ticket
  minted on a no-client-cert validation probe can never be resumed to bypass
  mTLS. This stays unconditional and is unaffected by everything below.
* **Resumption skips access control.** Ghostunnel enforces ACLs
  (`--allow-*` / `--verify-*`, OPA policies, SPKI pins) via
  `VerifyPeerCertificate`. Go does not invoke that callback on resumed
  handshakes — it restores `peerCertificates`/`verifiedChains` from the
  session state. So a resumed inbound connection currently reuses the
  authorization decision from its original handshake (Go still enforces cert
  expiry on resumption).
* **Ticket lifetime varies by cert source.** File-based sources
  (PEM/keystore/PKCS#11/keychain/ACME) rebuild the cached server config on
  every reload — the trust-store pointer swaps unconditionally, even when
  contents are unchanged — which discards the auto ticket keys and silently
  invalidates all outstanding tickets. The SPIFFE source caches its config
  forever, so ticket keys survive cert rotation there (Go rotates keys every
  24h and honors old keys for 7 days; `maxSessionTicketLifetime` is 7 days).

The three work items below (1) expose client-side resumption as an opt-in
flag, (2) make server-side ticket keys survive reloads consistently across
cert sources (SPIFFE parity), and (3) move enforcement from
`VerifyPeerCertificate` to `VerifyConnection` so that *every* handshake,
resumed or full, gets a complete, current verification: chain validation
against the live trust store plus the ACL/policy/pin decision. Item 3 is
what makes item 2 safe — with it, a resumed session is security-equivalent
to a full handshake, so keeping tickets alive across reloads costs nothing.

## Design overview: the VerifyConnection pipeline

The core design is a two-layer `VerifyConnection` on every authenticated
config:

1. **Source layer (certloader).** Each TLS config source installs a wrapper
   that guarantees `cs.VerifiedChains` reflects verification against the
   *current* trust material before anything else runs. On full handshakes in
   the standard modes Go already did this; on resumed handshakes the restored
   chains are stale, so the wrapper re-verifies `cs.PeerCertificates` from
   scratch. The wrapper owns the trust store, which is exactly why this layer
   lives in certloader and not in `auth`.
2. **ACL layer (auth).** Strict `VerifyConnectionServer` /
   `VerifyConnectionClient` callbacks evaluate the leaf of
   `cs.VerifiedChains` (or the pin against `cs.PeerCertificates` in pin
   mode) and fail closed when chains are absent. No knobs, no trust
   bypasses: the earlier idea of a `TrustExternallyVerifiedChains` escape
   hatch on `ACL` is rejected — it would let any caller silently disable
   chain validation with one boolean, and the invariant that makes such a
   bypass sound lives in a different package. The `auth` API stays safe by
   construction.

Per-source behavior of the source layer:

* **Cert/keystore/PKCS#11/keychain and ACME (server):** when
  `cs.DidResume`, re-verify the restored peer chain against the current
  `ClientCAs` pool (`x509.Verify` with client-auth EKU, intermediates from
  `cs.PeerCertificates[1:]`), replace `cs.VerifiedChains` with the fresh
  result, and fail the handshake on error. Full handshakes pass through
  untouched. This closes the gap where a CA-bundle rotation would not reach
  resumed sessions — including under `--allow-all`, where the chain check
  *is* the entire authorization decision. Without this, items 2+3 combined
  would be a regression for `--allow-all` users, whose evicted clients could
  keep resuming for up to 7 days; with it, CA rotation takes effect on the
  next handshake of any kind, as today.
* **Client side, same sources:** symmetric wrapper re-verifying the server
  chain (server-auth EKU) against the current `RootCAs` on resumed dials.
  Hostname re-verification is not re-run (the session cache is keyed by
  target address/SNI, so the peer cannot change identity within a cache
  entry); document this.
* **SPIFFE (both sides):** consolidate verification into the
  `VerifyConnection` wrapper instead of go-spiffe's
  `WrapVerifyPeerCertificate`. In SPIFFE mode Go's chains are always empty
  (`InsecureSkipVerify` / `RequireAnyClientCert`), so the wrapper runs
  `x509svid.ParseAndVerify` against the live bundle source on *every*
  handshake, populates `cs.VerifiedChains` from the result, then delegates
  to the ACL. This is strictly better than today: SVID chain verification
  now also runs on resumed handshakes (today it is skipped for them), and
  there is a single verification path instead of two callbacks with
  different coverage. Go aborts the handshake with an alert on
  `VerifyConnection` failure, so verification still completes before the
  handshake does. Update `spiffe_tls_config.go` comments and the tests that
  count `VerifyPeerCertificate` invocations.
* **SPKI pin mode (both sides):** no chain verification exists by design;
  the wrapper passes through and the ACL pin check runs against
  `cs.PeerCertificates[0]` on every handshake, resumed included.
* **ACME relaxed probe handshake: must clear `VerifyConnection`.** Unlike
  `VerifyPeerCertificate` (only invoked when a certificate message is
  processed, so never on the certless probe), Go calls `VerifyConnection`
  unconditionally on every handshake. The relaxed config is cloned from the
  main config and would inherit the ACL, see zero peer certificates, fail
  closed, and reject the CA's validator — breaking issuance/renewal. The
  relaxed-path builder must nil out `VerifyConnection` alongside
  `ClientAuth`/`ClientCAs`, with a regression test pinning this.

## Item 1: client-mode flag to enable session resumption

Client mode only; server mode keeps resumption enabled with no flag.

* **Flag** (`main.go`, client command block):

  ```go
  clientSessionResumption = clientCommand.Flag("session-resumption",
      "Cache TLS sessions and resume them when reconnecting to the target.").
      Default("false").Bool()
  ```

  Default `false` preserves current behavior. Kingpin auto-provides
  `--no-session-resumption` if the default ever flips.

* **Wiring** (`clientBackendDialer` in `main.go`): when the flag is set,
  assign `config.ClientSessionCache = tls.NewLRUClientSessionCache(32)`
  after `buildClientConfig`. All client sources clone the base config and
  `Clone()` carries the cache *pointer*, so the cache is shared across
  config rebuilds.

* **Identity freshness: flush the session cache on reload.** A resumed dial
  presents the session established under the *old* client certificate; if
  the cache survived a cert reload, a rotated client would keep presenting
  its stale identity until the ticket ages out or the server rejects it —
  surprising for the short-lived-cert use case ghostunnel targets. When a
  client config rebuild is triggered by a reload (trust-store pointer swap
  in `certTLSConfig.GetClientConfig`), install a *fresh* LRU cache on the
  rebuilt config. Trade-off, documented: client-side resumption does not
  persist across reloads (the window equals the reload interval); on the
  client side, presenting the current identity wins over resumption
  persistence. SPIFFE clients have no rebuild hook, so their cache persists
  across SVID rotation — the server-side re-verification from item 3 plus
  Go's expiry check bound this; document it as a known limitation.

* With item 3 in place, the `--verify-*` / policy / pin checks run on
  resumed dials too, so the flag needs no "verification is skipped on
  resumption" caveat.

## Item 2: server ticket keys survive reloads (SPIFFE parity)

Make file-based sources behave like SPIFFE: reloads must not rotate session
ticket keys.

**Chosen mechanism: an explicit ticket-key manager in certloader.** A small
shared `ticketKeyManager` owns the key material: it lazily generates and
rotates 32-byte keys on Go's own schedule (new key every 24h, old keys
retained 7 days), and each `GetServerConfig()` call applies the current key
set to the served config via `SetSessionTicketKeys` (first key encrypts new
tickets, all keys decrypt). Cheap generation-counter check per call so the
mutex-protected `SetSessionTicketKeys` only runs when the set actually
changed; rotation therefore propagates even if no reload ever rebuilds the
config. Used by the cert and ACME sources; SPIFFE keeps Go's auto-managed
keys (its config never rebuilds, so auto-rotation already works — behavior
is identical either way).

**Rejected alternative: rebuild-by-cloning-the-previous-config.** `Clone()`
does carry the auto ticket keys, but rebuild-from-previous inverts the
maintenance invariant from "base is the clean slate" to "every derived field
must be explicitly re-set, forever" — the ACME path already needs two
exceptions (`NextProtos` re-derivation, `GetConfigForClient` closure
rebinding), and a future trust-derived field that someone forgets to re-set
becomes a silent stale-config bug. The key manager keeps rebuild-from-base
untouched and confines the new state to one purpose-built, clock-injectable,
independently testable object.

* **`certloader/certtlsconfig.go` / `acmetlsconfig.go`:** each server-config
  source holds a `ticketKeyManager` (created with the source) and applies it
  in `GetServerConfig()`. Rebuild logic itself is unchanged.
* The ACME relaxed-probe path keeps its unconditional
  `SessionTicketsDisabled = true`, which fully disables ticket issuance for
  that handshake regardless of manager-installed keys.
* The HTTPS status listener serves from the same sources and inherits key
  persistence automatically.

**Semantics after items 2+3 together:** outstanding tickets survive reloads,
and a resumed session is security-equivalent to a full handshake — chain
verified against the current CA bundle, ACL/policy/pins evaluated, cert
expiry enforced. Process restart still invalidates all tickets (keys are
in-memory only). Multi-instance SO_REUSEPORT deployments still cannot resume
across instances (per-process keys); unchanged from today, document it.

## Item 3: switch enforcement from VerifyPeerCertificate to VerifyConnection

`VerifyConnection` is invoked by Go on both full and resumed handshakes, on
both client and server (verified against Go 1.25.1: `handshake_server.go`,
`handshake_server_tls13.go`, `handshake_client.go`,
`handshake_client_tls13.go` — all call it on the resumption paths). The
two-layer pipeline in the design overview is implemented as:

### auth package (`auth/auth.go`)

* Add `VerifyConnectionServer(cs tls.ConnectionState) error` and
  `VerifyConnectionClient(cs tls.ConnectionState) error` on `ACL`, sharing
  the existing check logic (CN/OU/SAN/URI matching, OPA evaluation, SPKI
  pins). Strict: leaf comes from `cs.VerifiedChains[0][0]`; empty chains
  fail closed (server) / fail closed unless pin mode handles it (client),
  exactly mirroring today's semantics. No bypass fields.
* Pin mode: refactor `verifySPKIPin` to take an `*x509.Certificate` and feed
  it `cs.PeerCertificates[0]` (`RawSubjectPublicKeyInfo` is already parsed).
  No pin semantics change.
* Keep `VerifyPeerCertificateServer`/`VerifyPeerCertificateClient` as thin
  deprecated wrappers over the shared internals — `auth` is an exported
  package with documented examples. The deprecation notice must state the
  *reason*: these callbacks are not invoked on resumed handshakes, so
  resumption-enabled servers using them do not re-check access control.
  Update `auth/doc_test.go` examples and the `PinningEnabled` doc comment.

### certloader

* Implement the source-layer wrapper (re-verification on resumed handshakes
  against live trust material; SPIFFE `ParseAndVerify` consolidation; pin
  passthrough) as described in the design overview. The wrapper composes
  with whatever `VerifyConnection` the base config carries, so `main.go`
  stays the single place that decides *policy* and certloader decides
  *verification freshness*.
* ACME: clear `VerifyConnection` in the relaxed-probe config (see design
  overview; regression test required).

### main.go

* `serverListen`: replace
  `config.VerifyPeerCertificate = serverACL.VerifyPeerCertificateServer`
  with `config.VerifyConnection = serverACL.VerifyConnectionServer`.
* `clientBackendDialer`: likewise switch to
  `config.VerifyConnection = clientACL.VerifyConnectionClient`.
* Status listener is unauthenticated (`NoClientCert`) and stays untouched.

### Behavior notes

* OPA policies, ACL flags, and pins are re-evaluated on every resumed
  connection — authorization changes take effect for resuming clients
  immediately. OPA evaluation (bounded by `OPAQueryTimeout`, up to
  `--connect-timeout`) now also gates resumed handshakes that used to be
  nearly free; a latency note for OPA users belongs in the release notes.
* Clients holding now-unauthorized tickets get a handshake failure on the
  resume attempt (alert) rather than a full-handshake rejection — same
  outcome, slightly different timing. Confirm existing integration tests
  still match; per the CLAUDE.md fixed-strings list,
  `"error on TLS handshake"` must keep appearing for rejects.

## Observability (small enabler, shared by all items)

Add a resumption marker to the TLS state description in `proxy/str.go` using
`ConnectionState().DidResume`. Rationale: operators currently cannot tell
whether resumption happens at all, and the integration tests for client-mode
resumption need it — CPython only exposes `session_reused` on client-side
sockets, and in client mode ghostunnel *is* the TLS client. Two caveats to
handle: this changes connection log lines that operators may be parsing
(call it out in release notes), and it becomes a new fixed log substring
that Python tests match — add it to the CLAUDE.md fixed-strings list and
land code and tests in lockstep.

## Tests

Go unit tests:

* `auth/auth_test.go`: port the ACL matrix to the `VerifyConnection`
  callbacks (build `tls.ConnectionState` fixtures); add cases for empty
  chains fail-closed and pins via `PeerCertificates`. Keep coverage on the
  deprecated wrappers.
* `certloader` wrapper tests: resumed-handshake re-verification — original
  handshake succeeds, trust store swapped to a pool that no longer contains
  the peer's CA, resumed handshake must *fail*; and the mirror case where
  the CA is still present, resumed handshake must succeed. SPIFFE: verify
  `ParseAndVerify` runs (and chains populate) on both full and resumed
  handshakes.
* `certloader` ticket-key manager tests: with an injected clock — key set
  stable within 24h, new encryption key after 24h, keys dropped after 7d;
  resumption works across a `Reload()` (behavioral test: serve TLS from a
  cert source, connect with a session-cache-equipped client, reload,
  reconnect, assert `DidResume`). Existing pointer-based cache-invalidation
  tests must still pass. **TLS 1.3 timing care:** `NewSessionTicket` arrives
  after the handshake, so tests must do a read/round-trip before reusing the
  session (or pin TLS 1.2), else they flake.
* `certloader/acmetlsconfig_test.go`: relaxed config has nil
  `VerifyConnection` (the renewal-breakage regression test) and keeps
  `SessionTicketsDisabled`; ticket persistence across trust-store rebuilds.
* `main` tests: flag defaults to false; when set, the dialer config carries
  a non-nil `ClientSessionCache`; server and client configs set
  `VerifyConnection` and no longer set `VerifyPeerCertificate` (any mode).
* End-to-end authorization-freshness test: server with a restrictive ACL,
  client resumes, resumed connection accepted; flip the OPA policy/ACL and
  assert a resumed connection is now rejected — the core guarantee of
  item 3. Companion test for the `--allow-all` + CA-rotation case: rotate
  the CA bundle, assert resumed connections from the old CA's clients fail.

Integration tests (`tests/`, Python):

* `test-server-resumption-survives-reload.py`: Python client saves its
  session, test triggers a reload (SIGHUP, or touch + `--timed-reload`),
  reconnects with the saved session, asserts `session_reused`. Pin
  `--max-tls-version TLS1.2` for deterministic session handling in CPython.
* `test-server-resumption-acl-enforced.py`: resumed connection against a
  server whose OPA policy/ACL no longer allows the client is rejected at
  handshake.
* `test-server-resumption-ca-rotation.py`: `--allow-all` server; rotate CA
  bundle + reload; resumed connection from a client of the old CA fails.
* `test-client-session-resumption.py`: ghostunnel client with the flag dials
  twice; assert the resumption marker appears in logs on the second
  connection, and does not appear without the flag.
* ACME renewal path: extend existing ACME integration coverage (or unit
  coverage if no live-ACME harness exists) to prove the validator probe
  still completes with an ACL configured — guarding against the
  `VerifyConnection` inheritance bug.
* Re-run the full suite (`go tool mage test:all`) — the VerifyConnection
  switch touches every authenticated handshake path, so the existing
  allow/deny tests are the main regression net. Also `go tool mage go:lint`.

## Docs

1. **`docs/getting-started/flags.md`** — add `--session-resumption` to the
   client-mode flags table, linking to the reloading doc for ticket-lifetime
   semantics.
2. **`docs/reference/manpage-linux.md` / `manpage-darwin.md`** — regenerate
   from kingpin help via the mage manpage target (`magefile.go`). The Linux
   page regenerates in CI/dev containers; the Darwin page needs a macOS run
   or a mechanical copy of the flag text.
3. **`docs/certificates/reloading.md`** — new subsection ("Session
   resumption and reloads") under "What Gets Reloaded": server-side reloads
   do not rotate session-ticket keys; resumed sessions remain resumable for
   up to the 7-day ticket window, and every resumed handshake re-verifies
   the peer chain against the current CA bundle and re-runs access control,
   so reloading trust material takes effect immediately for all handshakes;
   client-side, a reload flushes the session cache so the new identity is
   presented on the next dial; restart the process to hard-invalidate all
   server tickets.
4. **`docs/security/general.md`** — section on session resumption semantics:
   server-side tickets on by default; verification and access control run on
   every handshake including resumed ones (chain vs. current trust store,
   ACL/policies/pins, cert expiry); SPIFFE SVID verification now also runs
   on resumed handshakes; client-side resumption is opt-in via
   `--session-resumption`; hostname verification on resumed client dials is
   bound by the session-cache key rather than re-run; ACME validation-probe
   handshakes always have resumption disabled and carry no access-control
   callback (cross-reference `acme.md`).
5. **`docs/security/access-flags.md`** — note that ACL evaluation happens
   per handshake (full and resumed) and that OPA policies are consulted on
   each connection, including resumed ones.
6. **`README.md`** — likely no change (it defers flag detail to the docs
   site); optionally one line in the client-mode overview.
7. **`CLAUDE.md` / `AGENTS.md`** — add the new resumption log marker to the
   fixed-log-strings list.
8. **Release notes** (`releases/`) — entry covering the new flag, the
   ticket-persistence change, the VerifyConnection migration (including the
   OPA-on-resumed-handshakes latency note and the connection-log format
   change), following the existing notes format.

## Suggested commit sequence

1. auth: add strict `VerifyConnection{Server,Client}`, refactor pin check,
   deprecate old callbacks with reasoned notices (with tests).
2. certloader: source-layer `VerifyConnection` wrappers — resumed-handshake
   chain re-verification for cert/ACME, SPIFFE `ParseAndVerify`
   consolidation, ACME relaxed-config `VerifyConnection` clear (with tests,
   including the ACME regression test).
3. main: switch server/client wiring to `VerifyConnection` (with tests).
4. certloader: `ticketKeyManager` + wiring into cert/ACME server configs
   (with clock-injected unit tests and the resumption-across-reload
   behavioral test).
5. main: `--session-resumption` client flag + LRU session cache + flush on
   reload (with tests).
6. proxy: resumption marker in connection log strings + integration tests +
   CLAUDE.md fixed-strings update.
7. Docs + release notes.

Each step keeps `go tool mage test:all` green on its own.
