# Ghostunnel Code Quality & Bug Audit

**Date:** 2026-06-21
**Branch:** `claude/code-quality-agent-analysis-xw5wbu`
**Commit audited:** `27f9125`
**Scope:** Static analysis of the whole codebase, split by area of concern.

## Methodology

The codebase was divided into six areas of concern along package boundaries.
Each area was audited by an independent multi-agent pipeline:

1. **Spec agent** — wrote a specification of what a human operator would
   reasonably expect the feature to do (security guarantees, edge-case
   handling, lifecycle).
2. **Check agent** — read the actual code and listed every deviation from
   the spec as a *candidate* bug.
3. **Verify agent** — independently re-read the code for each candidate,
   rejected false positives, and assigned a final priority.

Per the audit request, **only HIGH and MEDIUM priority findings are surfaced
below**; LOW-priority findings (cosmetic issues, latent gaps guarded by
current callers, lint smells) were dropped. A count of dropped LOW items is
given per area for transparency.

### Areas audited

| Area | Packages / files | HIGH | MEDIUM | LOW (dropped) |
|------|------------------|:----:|:------:|:-------------:|
| Access control | `auth/`, `wildcard/` | 0 | 1 | 1 |
| Policy / OPA | `policy/` | 0 | 0 | 1 |
| Certificate loading & TLS | `certloader/`, `certstore/`, `tls.go` | 1 | 1 | 4 |
| Proxy | `proxy/` | 0 | 0 | 1 |
| Socket & lifecycle | `socket/`, `signals.go`, `status*.go`, `landlock*.go` | 1 | 0 | 0 |
| Main / CLI | `main.go` | 0 | 1 | 2 |
| **Total (after consolidation)** | | **2** | **3** | — |

> The client-side OPA validation issue was independently reported by both the
> Access-control and Main/CLI pipelines; it is consolidated into a single
> MEDIUM finding (M1) below.

---

## HIGH priority

### H1 — Server trusts the entire public WebPKI when `--cacert` is omitted

- **Area:** Certificate loading & TLS
- **Location:** `certloader/loader.go:80-83` → `certloader/certtlsconfig.go:73`; client-auth mode set in `tls.go` (`RequireAndVerifyClientCert`); flag wiring in `main.go`
- **Impact:** `LoadTrustStore("")` returns `x509.SystemCertPool()`. No flag
  validation requires `--cacert` in server mode, and the server config sets
  `ClientAuth = tls.RequireAndVerifyClientCert`. Consequently, a server
  started with a key/cert keystore but **no `--cacert`** sets
  `ClientCAs = SystemCertPool()` and verifies client certificates against the
  **entire public WebPKI** instead of a private CA.
  - With `--allow-all`, this is a **complete client-authentication bypass**:
    any client presenting *any* publicly-trusted certificate is accepted.
  - With a CN/DNS/URI allowlist, an attacker who can obtain a publicly-trusted
    certificate whose CN/SAN matches an allow rule (e.g. a hostname they
    control) is accepted — expanding the trust boundary from "operator's
    private CA" to "all of WebPKI."

  The flag help text ("uses system trust store by default") makes this silent
  and reachable in ordinary operation.
- **Suggested fix:** In server mode, require an explicit trust anchor
  (`--cacert`) whenever client authentication is enabled (i.e. not
  `--disable-authentication`), **or** never fall back to the system pool for
  the server `ClientCAs` direction — restrict the system-pool default to
  client-mode `RootCAs` only, and fail closed otherwise.

### H2 — Readiness endpoint can return `200 OK` during graceful shutdown

- **Area:** Socket & lifecycle
- **Location:** `status.go:159` (root causes: `Listening()` at `status.go:99-106`; un-stopped `reloadHandler` at `signals.go:99-106`)
- **Impact:** The periodic timed-reload goroutine (`reloadHandler`, active
  when `--timed-reload` is set) is never stopped on shutdown. On SIGTERM,
  `shutdownFunc()` calls `Stopping()` (sets `stopping=true, listening=false`),
  but the proxy keeps draining in-flight connections for up to
  `shutdownTimeout`. During that window a racing `reload()` calls
  `Listening()`, which sets `listening=true` and does **not** clear
  `stopping`. Because readiness is computed as
  `resp.Ok = s.listening && resp.BackendOk` — ignoring `stopping` — the
  `/_status` endpoint then returns **HTTP 200** even though `resp.Message`
  correctly reports `"stopping"`. A load balancer or orchestrator keying on
  HTTP status / `Ok` keeps routing new traffic to a draining instance,
  defeating graceful drain.

  The existing test `TestStatusHandlerStopping` only exercises
  `Listening()→Stopping()` (which correctly yields 503), so the reversed
  `Stopping()→Listening()` ordering that triggers this bug is uncaught.
- **Suggested fix:**
  1. Make readiness honor the terminal state at `status.go:159`:
     `resp.Ok = s.listening && !s.stopping && resp.BackendOk`.
  2. Defense-in-depth: stop `reloadHandler` on shutdown (select on a
     done channel / shutdown-derived context) so reloads can't race the drain.

---

## MEDIUM priority

### M1 — Client-mode OPA access control is not mutually exclusive with `--verify-*`, contradicting its own documentation

- **Area:** Access control / Main-CLI (reported by both pipelines)
- **Location:** doc at `auth/auth.go:66-68`; client ACL logic at `auth/auth.go:118-131` & `:180-193`; missing guard in `validateClientOPA` at `main.go:484-493`; server guard present at `main.go:401-402`
- **Impact:** The `AllowOPAQuery` field comment states it "is exclusive with
  all other options," but in both server and client verification the OPA query
  is evaluated **last and only when no other ACL field matched** — i.e. it is
  OR'd (disjunctive) with CN/OU/DNS/IP/URI. Server mode hides this because
  `main.go:401-402` rejects combining OPA flags with other access flags at the
  CLI layer. **Client mode has no equivalent check.** A client run with, e.g.,
  `--verify-query` plus `--verify-cn foo` is accepted and gets OR semantics:
  the peer is trusted if *either* the CN matches *or* the OPA policy allows —
  so a server whose cert CN is `foo` is trusted even if the OPA policy would
  deny it (and vice versa). This is not a hard bypass (the behavior is a
  well-defined OR and hostname verification still applies), but authorization
  is **looser than the documentation an operator relies on**, and the
  client/server validation asymmetry is surprising.
- **Suggested fix:** Add a client-side exclusivity check mirroring the server
  (error when OPA flags are combined with other `--verify-*` flags), **or**, if
  disjunctive OR is the intended behavior, correct the `auth.go:66-68` comment
  to state OPA is OR'd like the other options. Enforcing exclusivity to match
  the server is the cleaner, less surprising choice.

### M2 — Side effects (including outbound metrics) start before mode-specific flag validation

- **Area:** Main / CLI
- **Location:** `main.go:597-633` (mode-specific validation runs later, at `:630` server / `:677` client)
- **Impact:** Inside `run()`, the graphite goroutine, the Prometheus provider
  goroutine, the CA trust-store disk load (`certloader.LoadTrustStore`), and
  `sqmetrics.NewMetrics` all execute **before** mode-specific validation. With
  `--metrics-url` set, `sqmetrics.NewMetrics` immediately launches
  `publishMetrics()`, so the first outbound metrics POST can be in flight
  before credential/target/ACME/access-control flags are validated. A config
  destined to be rejected still triggers background goroutines, a file read,
  and outbound network traffic before the process exits non-zero. No security
  bypass (the process still aborts), but it violates "validate before side
  effects" and can leak intent / cause spurious connections from a
  misconfigured invocation.
- **Suggested fix:** Move the combined mode-specific validation
  (`serverValidateFlags`/`clientValidateFlags`) to immediately after
  `applyFlagImplications()` and before the metrics/trust-store block.

### M3 — Platform keychain `Store`/`Identity` handles leaked on every certificate reload

- **Area:** Certificate loading & TLS
- **Location:** `certloader/certstore_enabled.go:74-176` (handle opened at `:80`, never closed)
- **Impact:** `certstore.Store` and `certstore.Identity` both expose `Close()`
  (documented in `certstore/certstore.go` as releasing manually-managed
  native memory / handles). `Reload()` opens a store and enumerates identities
  on every reload but never closes the store or the enumerated identities.
  Certificate reload runs on SIGHUP and on the periodic `reloadHandler` timer,
  so native keychain handles/memory accumulate over the process lifetime on
  the macOS/Windows CGO builds — an unbounded resource leak for a
  long-running, periodically-reloading proxy.
- **Suggested fix:** `defer store.Close()` after a successful open, and
  `Close()` the non-chosen candidate identities (retaining only the chosen
  identity for the lifetime of the cached certificate).

---

## Areas found clean (no HIGH/MEDIUM findings)

- **Policy / OPA (`policy/`):** Reload is correct and race-safe — the prepared
  query lives behind an atomic pointer, the store happens only after a
  successful compile (last-good-wins on reload failure), and concurrent
  `Eval`/`Reload` cannot produce torn reads. No fail-open or auth-bypass.
  (1 LOW dropped: a latent nil-guard in `Eval`, unreachable today.)
- **Proxy (`proxy/`):** PROXY-protocol-v2 header construction, the
  connection-limit semaphore (acquire-before-accept, release on every
  early-return/panic path), `fuse` goroutine join, and half-open handling were
  all verified sound. (1 LOW dropped: `MaxConnLifetime` cap can be exceeded by
  at most `CloseTimeout`.)

## Notable candidates investigated and cleared

These were flagged by check agents but **rejected** during verification —
recorded here because they are the kind of issue worth knowing was checked:

- **SPIFFE + operator ACL interaction (certloader):** Verified **correct**.
  `WrapVerifyPeerCertificate` runs `x509svid.ParseAndVerify`, which validates
  the chain against the SPIFFE bundle and passes a **non-empty**
  `verifiedChains` to the chained operator ACL verifier. The
  `len(verifiedChains)==0` fail-closed branch is *not* spuriously triggered,
  and the SPIFFE `RequireAnyClientCert` / `InsecureSkipVerify` settings are the
  required design (verification is delegated to the callback), not a downgrade.
- **`--allow-all` + `--disable-authentication` (main):** Correctly rejected by
  mutually-exclusive CLI guards; secure default (`RequireAndVerifyClientCert`,
  TLS 1.2 minimum) intact.
- **Wildcard/glob matcher (access control):** Regex anchoring, `*` →
  single-segment non-empty, `**` end-only, case-sensitivity, and IP/URI/DNS SAN
  matching all verified correct; no auth-bypass in the matching logic.

---

## Dropped LOW-priority items (not detailed per request)

For transparency, the following counts of LOW-priority findings were
identified and intentionally **not** surfaced as actionable bugs:
Access control (1), Policy/OPA (1), Certloader/TLS (4: non-atomic cert+pool
publish, SPIFFE source/client `Close()` never called on shutdown ×2, ACME
startup backoff ignores context cancellation), Proxy (1), Main/CLI (2). These
are cosmetic, lint-smell, or latent-but-currently-guarded issues; they can be
revisited as hardening work but pose no realistic security or reliability risk
in current configurations.
