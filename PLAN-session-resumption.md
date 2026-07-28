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
cert sources (SPIFFE parity), and (3) move ACL enforcement from
`VerifyPeerCertificate` to `VerifyConnection` so access control runs on
*every* handshake, resumed or full. Item 3 is what makes item 2 safe: with it,
a resumed session after a CA-bundle or policy change is still subject to a
fresh authorization decision.

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
  assign `config.ClientSessionCache = tls.NewLRUClientSessionCache(32)` after
  `buildClientConfig`. No certloader changes needed: all client sources clone
  the base config and `Clone()` carries the cache *pointer*, so one shared
  cache survives trust-store rebuilds and resumption keeps working across
  reloads.

* With item 3 in place, the `--verify-*` / policy / pin checks run on resumed
  dials too, so the flag needs no "verification is skipped on resumption"
  caveat.

## Item 2: server ticket keys survive reloads (SPIFFE parity)

Make file-based sources behave like SPIFFE: reloads must not rotate session
ticket keys. Key enabler: `tls.Config.Clone()` copies the auto-managed ticket
keys along with their creation timestamps, so Go's rotation schedule (new key
every 24h, old keys honored for 7 days) continues uninterrupted across
rebuilds.

* **`certloader/certtlsconfig.go`** (`GetServerConfig`): when a previous
  cached config exists, rebuild by cloning it instead of the pristine base:
  `config := prev.config.Clone()`, then re-apply only the trust-store-derived
  field (`ClientCAs = pool`, still skipped under `RequireAnyClientCert` pin
  mode). The base never changes after startup, so `prev.Clone()` is
  equivalent to `base.Clone()` plus callbacks plus ticket keys. First build
  is unchanged. Update the `cachedTLSConfig` doc comment, which currently
  describes rebuild-from-base semantics. `GetClientConfig` is unchanged.
* **`certloader/acmetlsconfig.go`** (`buildServerConfig`): same carry-forward,
  with two ACME-specific cares: rebuild `NextProtos` from `a.base` (cloning
  the previous config would double-append `acme-tls/1`), and rebind the
  `GetConfigForClient` closure to the newly built config. The relaxed-probe
  path keeps its unconditional `SessionTicketsDisabled = true`.
* **`certloader/spiffe_tls_config.go`**: no change; it is the reference
  behavior.
* The HTTPS status listener uses its own source-built config and inherits the
  fix automatically.

**Semantic change to call out in the PR:** a CA-bundle reload no longer
invalidates outstanding tickets. With item 3, resumed sessions still get a
fresh ACL/policy/pin decision on every handshake; what a resumed session does
*not* get is chain re-verification against the updated CA bundle (bounded by
the 7-day ticket window and Go's cert-expiry check on resumption). Process
restart remains the hard invalidation for all tickets. A possible follow-up
(out of scope here) is re-verifying `cs.PeerCertificates` against the current
trust store inside `VerifyConnection`, which would close that remaining gap.

## Item 3: switch ACL enforcement from VerifyPeerCertificate to VerifyConnection

`VerifyConnection` is invoked by Go on both full and resumed handshakes, on
both client and server (verified against Go 1.25.1: `handshake_server.go`,
`handshake_server_tls13.go`, `handshake_client.go`,
`handshake_client_tls13.go` — all call it on the resumption paths). Moving
the ACL there means every connection gets a live authorization decision.

### auth package (`auth/auth.go`)

* Add `VerifyConnectionServer(cs tls.ConnectionState) error` and
  `VerifyConnectionClient(cs tls.ConnectionState) error` on `ACL`, sharing
  the existing check logic (CN/OU/SAN/URI matching, OPA evaluation, SPKI
  pins).
* Leaf selection: use `cs.VerifiedChains[0][0]` when chains are present. On
  resumed connections Go restores `VerifiedChains` from the session state, so
  the standard (non-SPIFFE, non-pin) paths always have chains, full or
  resumed. Empty chains keep failing closed on the server side, as today.
* Pin mode: `verifySPKIPin` currently parses `rawCerts[0]`; refactor it to
  take an `*x509.Certificate` and feed it `cs.PeerCertificates[0]`
  (`RawSubjectPublicKeyInfo` is already parsed). No pin semantics change.
* **SPIFFE composition (the subtle part).** In SPIFFE mode the transport uses
  `InsecureSkipVerify` / `RequireAnyClientCert` and delegates chain building
  to go-spiffe: `WrapVerifyPeerCertificate` runs `x509svid.ParseAndVerify`
  and passes its *own* verified chains to the wrapped callback, discarding
  Go's (empty) ones. Consequently `cs.VerifiedChains` is empty in SPIFFE mode
  and the new callbacks cannot rely on it there. Plan: add an explicit ACL
  field (e.g. `TrustExternallyVerifiedChains bool`, exact name at
  implementation time) that permits falling back to `cs.PeerCertificates[0]`
  when chains are absent. Only the SPIFFE path sets it, on the grounds that
  go-spiffe verifies the chain on full handshakes and a resumed session's
  peer certs were verified when the ticket was issued. All other modes keep
  strict fail-closed behavior on empty chains.
  * `certloader/spiffe_tls_config.go` keeps wrapping
    `VerifyPeerCertificate` for SVID chain verification
    (`WrapVerifyPeerCertificate(nil, ...)` degrades cleanly to
    `VerifyPeerCertificate(bundle, authorizer)` when the base callback is
    nil), while the ACL rides on `VerifyConnection` cloned from the base.
    Update the comment blocks that currently describe the ACL being wrapped.
  * Known limitation to document: on SPIFFE *resumed* handshakes the SVID
    chain verification itself is skipped (as it is today); the ACL check
    still runs against the restored leaf.
* Keep `VerifyPeerCertificateServer`/`VerifyPeerCertificateClient` as thin
  deprecated wrappers over the shared internals — `auth` is an exported
  package with documented examples, so removing them would break importers.
  Update `auth/doc_test.go` examples and the `PinningEnabled` doc comment to
  reference the new methods.

### main.go

* `serverListen`: replace
  `config.VerifyPeerCertificate = serverACL.VerifyPeerCertificateServer` with
  `config.VerifyConnection = serverACL.VerifyConnectionServer`.
* `clientBackendDialer`: likewise switch to
  `config.VerifyConnection = clientACL.VerifyConnectionClient`.
* Status listener is unauthenticated (`NoClientCert`) and stays untouched.

### Behavior notes

* OPA policies, ACL flags, and pins are now re-evaluated on every resumed
  connection — authorization changes take effect for resuming clients
  immediately, not only after ticket expiry. OPA evaluation cost now also
  applies per resumed handshake (still cheap relative to a full handshake,
  and it is the point of the change).
* Handshake failures from `VerifyConnection` surface as handshake errors just
  like `VerifyPeerCertificate` failures; integration tests that assert
  auth-rejection behavior must be re-run to confirm no fixed log strings
  changed (per the CLAUDE.md fixed-strings list, `"error on TLS handshake"`
  must keep appearing for rejects).

## Observability (small enabler, shared by all items)

Add a resumption marker to the TLS state description in `proxy/str.go` using
`ConnectionState().DidResume`. Rationale: operators currently cannot tell
whether resumption happens at all, and the integration tests for client-mode
resumption need it — CPython only exposes `session_reused` on client-side
sockets, and in client mode ghostunnel *is* the TLS client. This adds a new
log substring that tests will match; code and tests must land in lockstep.

## Tests

Go unit tests:

* `auth/auth_test.go`: port the ACL matrix to the `VerifyConnection`
  callbacks (build `tls.ConnectionState` fixtures); add cases for empty
  chains fail-closed, the SPIFFE fallback knob, and pins via
  `PeerCertificates`. Keep coverage on the deprecated wrappers.
* `certloader/certtlsconfig_test.go`: behavioral test — serve TLS from a cert
  source, connect with a session-cache-equipped test client, `Reload()` (the
  trust-store pointer swaps), reconnect with the same cache, assert
  `DidResume`. Existing pointer-based cache-invalidation tests must still
  pass (the config pointer still rotates; only ticket keys persist).
* `certloader/acmetlsconfig_test.go`: same resumption-across-rebuild
  assertion; `NextProtos` contains exactly one `acme-tls/1` after repeated
  rebuilds; the existing relaxed-config `SessionTicketsDisabled` test keeps
  passing.
* `main` tests: flag defaults to false; when set, the dialer config carries a
  non-nil `ClientSessionCache`; server and client configs set
  `VerifyConnection` (and no longer set `VerifyPeerCertificate` outside
  SPIFFE mode).
* End-to-end resumption + authz test: server with a restrictive ACL, client
  resumes, assert the resumed connection is accepted; flip the ACL (e.g. OPA
  policy reload) and assert a resumed connection is now rejected — the core
  guarantee of item 3.

Integration tests (`tests/`, Python):

* `test-server-resumption-survives-reload.py`: Python client saves its
  session, test triggers a reload (SIGHUP, or touch + `--timed-reload`),
  reconnects with the saved session, asserts `session_reused`. Pin
  `--max-tls-version TLS1.2` for deterministic session handling in CPython.
* `test-server-resumption-acl-enforced.py`: resumed connection against a
  server whose OPA policy/ACL no longer allows the client is rejected at
  handshake.
* `test-client-session-resumption.py`: ghostunnel client with the flag dials
  twice; assert the resumption marker appears in logs on the second
  connection, and does not appear without the flag.
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
   resumption and reloads") under "What Gets Reloaded": reloads do not rotate
   session-ticket keys; resumed sessions remain resumable across CA-bundle
   changes for up to the 7-day ticket window (24h key rotation, cert expiry
   still enforced); access control is re-evaluated on every handshake
   including resumed ones (item 3); restart the process to hard-invalidate
   all tickets. This documents the deliberate semantic shift of item 2.
4. **`docs/security/general.md`** — section on session resumption semantics:
   server-side tickets are on by default; access control (`--allow-*`,
   policies, pins) is enforced on all handshakes including resumed ones via
   `VerifyConnection`; what resumption does *not* re-check (chain validation
   against the current CA bundle, SPIFFE SVID chain verification on resumed
   handshakes); client-side resumption is opt-in via `--session-resumption`;
   ACME validation-probe handshakes always have resumption disabled
   (cross-reference `acme.md`, which already documents that and needs no
   change).
5. **`docs/security/access-flags.md`** — note that ACL evaluation happens per
   handshake (full and resumed) and that OPA policies are consulted on each
   connection.
6. **`README.md`** — likely no change (it defers flag detail to the docs
   site); optionally one line in the client-mode overview.
7. **Release notes** (`releases/`) — entry for the next release covering the
   new flag, the ticket-persistence change, and the VerifyConnection
   migration, following the existing notes format.

## Suggested commit sequence

1. auth: add `VerifyConnection{Server,Client}`, refactor pin check, deprecate
   old callbacks (with tests).
2. main: switch server/client wiring to `VerifyConnection`; SPIFFE
   composition changes in certloader (with tests).
3. certloader: ticket-key carry-forward across rebuilds for cert + ACME
   sources (with tests).
4. main: `--session-resumption` client flag + LRU session cache (with tests).
5. proxy: resumption marker in connection log strings + integration tests.
6. Docs + release notes.

Each step keeps `go tool mage test:all` green on its own.
