# Ghostunnel Performance Analysis

This document collects the results of a performance review of the Ghostunnel
codebase, focused on the per-connection hot path (accept → TLS handshake →
authorization → backend dial → data copy) as well as steady-state background
costs. Findings are ordered by estimated impact. Each item lists the relevant
code, why it costs time or memory, a suggested fix, and any correctness or
security caveats the fix would need to address.

Nothing here is a functional bug — Ghostunnel's hot path is already in good
shape (pooled copy buffers, prepared OPA queries, atomic cert reloads, a
splice-aware `io.CopyBuffer` workaround, accept-loop backoff). The items below
are opportunities, not defects.

## Summary

| # | Finding | Area | Impact | Effort |
|---|---------|------|--------|--------|
| 1 | TLS session resumption is effectively impossible (both modes) | `certloader`, `tls.go` | High for connection-heavy workloads | Medium |
| 2 | `tls.Config.Clone()` on every accept/dial | `certloader` | Medium (allocations; root cause of #1) | Medium |
| 3 | `runtime.GOMAXPROCS(runtime.NumCPU())` defeats Go 1.25 container awareness | `main.go` | Medium in CPU-limited containers | Trivial |
| 4 | OPA policy evaluated per handshake with the full `x509.Certificate` as input | `auth` | Medium for `--allow-policy` users | Small–Medium |
| 5 | Metrics reporters run at a hardcoded 1s interval, ignoring `--metrics-interval` | `main.go` | Low (steady-state idle cost) | Trivial |
| 6 | `wildcard.Matcher.Matches` allocates a `[]byte` copy of its input | `wildcard` | Low | Trivial |
| 7 | `intersectsURI` re-serializes URI SANs in the inner loop | `auth` | Low | Trivial |
| 8 | `peerCertificatesString` copies `ConnectionState` twice per call | `proxy` | Low | Trivial |
| 9 | Miscellaneous (ACL scans, reload path, buffer sizing, single accept loop) | various | Low / situational | — |

---

## 1. TLS session resumption never succeeds, so every connection pays a full handshake

**Impact: High** for workloads with many short-lived connections (the common
case for a TCP proxy fronting request/response protocols). This is the single
largest CPU/latency opportunity in the codebase.

The dominant per-connection cost in Ghostunnel is the TLS handshake:
certificate chain verification plus asymmetric signing/verification on both
sides (typically several hundred microseconds to >1ms of CPU per side for
ECDSA/RSA, plus an extra network round trip). TLS session resumption exists
precisely to amortize that cost, but Ghostunnel cannot currently benefit from
it in either direction:

### Server mode: per-connection config clones get fresh session-ticket keys

`certloader.Listener` derives a brand-new `tls.Config` for **every accepted
connection**:

- `certloader/listener.go:48` — `tls.Server(c, l.config.GetServerConfig())`
- `certloader/certtlsconfig.go:70-75` — `GetServerConfig` does
  `c.base.Clone()` and stamps `GetCertificate`/`ClientCAs` on the clone.

`crypto/tls` generates session-ticket keys lazily, on first use, and stores
them *inside the config*. The base config here never performs a handshake, so
it never generates keys; every per-connection clone generates its **own**
random ticket keys. A session ticket issued on connection *N* can therefore
never be decrypted by the config used for connection *N+1*. The result is that
server-side resumption silently never succeeds — every reconnecting client
does a full handshake, forever. The same pattern exists in the SPIFFE and ACME
sources (`certloader/spiffe_tls_config.go:112`, `certloader/acmetlsconfig.go:245`).

### Client mode: no `ClientSessionCache`

`buildClientConfig` (`tls.go:159`) never sets `tls.Config.ClientSessionCache`,
so Ghostunnel-as-client performs a full handshake against the backend for
every single proxied connection. Since `Clone()` copies the cache *pointer*,
setting one `tls.NewLRUClientSessionCache` on the base config would be shared
correctly by all per-dial clones — but today there is none.

### Suggested fix

1. Stop deriving a fresh config per connection (see finding #2): cache the
   derived server/client `tls.Config` and rebuild it only when the underlying
   certificate or trust store actually changes (the `atomic.Pointer` values in
   `certloader/certificate.go` make "did it change" a cheap pointer-identity
   check). A stable long-lived server config gets stable auto-rotating ticket
   keys from crypto/tls for free.
2. Set `ClientSessionCache: tls.NewLRUClientSessionCache(0)` in
   `buildClientConfig`.

### Security caveat (must be handled, not optional)

Go does **not** invoke `Config.VerifyPeerCertificate` on resumed connections —
from the Go 1.25 `crypto/tls` docs: *"This callback is not invoked on resumed
connections, as certificates are not re-verified on resumption."* Ghostunnel's
entire ACL enforcement (`auth.ACL.VerifyPeerCertificateServer` /
`VerifyPeerCertificateClient`, wired up in `main.go:780` and `main.go:1023`)
lives in that callback. Today that's moot — resumption never happens — but
enabling resumption without moving enforcement would let a resumed session
skip ACL/OPA re-evaluation for the lifetime of a ticket.

The fix is to move (or duplicate) ACL enforcement into
`Config.VerifyConnection`, which is documented to run *"for all connections,
including resumptions, regardless of InsecureSkipVerify or ClientAuth
settings"*, using `ConnectionState.VerifiedChains`. Note that crypto/tls does
retain some safety on its own (it stores verified chains in the session state,
refuses resumption if the client cert has expired, and re-checks `ClientAuth`
requirements — see `checkForResumption` in `handshake_server_tls13.go`), but
ACL and policy decisions are Ghostunnel's responsibility.

This also composes with hot-reload semantics: rebuilding the cached config on
cert/trust-store reload naturally rotates ticket keys, so old tickets are
invalidated whenever the CA bundle or ACL-relevant configuration changes.

### How to validate

Add an integration test that makes two consecutive connections with the same
session cache and asserts `ConnectionState.DidResume` on the second; benchmark
connection setup rate before/after (e.g. `openssl s_time`, or a Go benchmark
dialing in a loop with a shared session cache).

---

## 2. `tls.Config.Clone()` per accepted/dialed connection

**Impact: Medium** — this is the mechanism behind finding #1, but it is also a
standalone allocation cost.

Every accept clones the base server config
(`certloader/certtlsconfig.go:70-75`), and every backend dial clones the base
client config (`certloader/dialer.go:44-45` → `certtlsconfig.go:63-68`).
`tls.Config` is a large struct (~750 bytes) with a mutex, and `Clone()` takes
a lock and copies every field — per connection, on top of the two 32 KiB pool
buffers and goroutines that are actually needed.

The only reason for the per-connection clone is to pick up a possibly-reloaded
trust store (`ClientCAs`/`RootCAs`); the certificate itself is already fetched
dynamically via the `GetCertificate`/`GetClientCertificate` callbacks. Since
`baseCertificate` stores the pool in an `atomic.Pointer[x509.CertPool]`
(`certloader/certificate.go:29`), the derived config can be cached in an
`atomic.Pointer[tls.Config]` and rebuilt only when `GetTrustStore()` returns a
different pointer than the one the cached config was built from:

```go
func (c *certTLSConfig) GetServerConfig() *tls.Config {
    pool := c.cert.GetTrustStore()
    if cached := c.cached.Load(); cached != nil && cached.pool == pool {
        return cached.config
    }
    // slow path: clone base, set callbacks/ClientCAs, publish to c.cached
    ...
}
```

Alternatively, use a single long-lived config whose `GetConfigForClient`
callback returns the cached derived config. Either way, steady-state accepts
become allocation-free with respect to TLS config, and finding #1's ticket-key
problem disappears.

---

## 3. `runtime.GOMAXPROCS(runtime.NumCPU())` disables Go 1.25's container-aware scheduling

**Impact: Medium** for containerized deployments with CPU limits; zero
elsewhere. **Effort: trivial.**

`main.go:553`:

```go
func run(args []string) error {
    runtime.GOMAXPROCS(runtime.NumCPU())
```

This line has been a no-op since Go 1.5 (it restates the default) — but as of
Go 1.25 (which this project targets, per `go.mod`), it is actively harmful in
containers: the Go 1.25 runtime now derives `GOMAXPROCS` from the cgroup CPU
quota and *updates it dynamically* as the quota changes. Calling
`runtime.GOMAXPROCS()` explicitly disables both behaviors.

Concretely: Ghostunnel running in a Kubernetes pod with `limits.cpu: 2` on a
64-core node gets `GOMAXPROCS=64` instead of 2, which means more OS threads
than the quota can service — CFS throttling, longer GC pauses, and scheduling
latency spikes on the proxy path.

**Fix:** delete the line.

---

## 4. OPA policy evaluation cost per handshake

**Impact: Medium**, only for deployments using `--allow-policy`/`--allow-query`
(or the client-side `--verify-*` equivalents).

The good news: policies are compiled once into a `rego.PreparedEvalQuery` and
atomically swapped on reload (`policy/loader.go`), so per-handshake evaluation
does not re-parse anything.

The remaining per-handshake costs, in `auth/auth.go:118-131` and `:180-193`:

1. The eval input is the entire `*x509.Certificate` struct
   (`map[string]any{"certificate": cert}`). OPA converts arbitrary Go values
   to its AST via reflection/JSON round-tripping, and `x509.Certificate` is a
   very large struct — raw DER bytes, every extension, the full public key —
   most of which typical policies never inspect. Constructing a slim input
   (subject, SANs, validity, issuer, fingerprint — whatever the documented
   policy interface promises) would cut most of that conversion cost.
   *Caveat:* this changes the data visible to policies, so it would need to be
   an opt-in or major-version change; the current shape is effectively API.
2. `context.WithTimeout` + a `map[string]any` allocation per handshake —
   negligible next to (1), but the input map for a given cert could be built
   once and reused for both branches.

A further option for high connection rates is memoizing the allow/deny
decision keyed by (leaf certificate fingerprint, policy generation) with a
short TTL, so N connections from the same client cost one evaluation. The
policy-generation component of the key (bumped on `Reload`) keeps hot-reload
semantics intact.

---

## 5. Metrics reporters ignore `--metrics-interval` and run every second

**Impact: Low** (steady-state background cost), **Effort: trivial.**

`main.go:596-609`:

```go
go graphite.Graphite(metrics.DefaultRegistry, 1*time.Second, *metricsPrefix, *metricsGraphite)
...
pClient := prometheusmetrics.NewPrometheusProvider(metrics.DefaultRegistry, *metricsPrefix, "", prometheus.DefaultRegisterer, 1*time.Second)
```

Both the Graphite reporter and the go-metrics→Prometheus bridge are hardcoded
to a 1-second interval even though `--metrics-interval` (default 30s) exists
and is honored by the JSON/URL reporter. Each tick walks the entire registry
under its lock and (for Graphite) writes to the network. On an idle or lightly
loaded proxy this is the majority of its background CPU wakeups; on a busy one
the registry walk contends with the per-connection counter/timer updates in
`proxy/proxy.go:51-59`.

**Fix:** pass `*metricsInterval` to both. (The Prometheus bridge is also
registered unconditionally, even when nothing scrapes `/_metrics` — it could
be started lazily or only when `--status` is set.)

---

## 6. `wildcard.Matcher.Matches` allocates per call

**Impact: Low**, **Effort: trivial.**

`wildcard/matcher.go:198-200`:

```go
func (rm regexpMatcher) Matches(input string) bool {
    return rm.pattern.Match([]byte(input))
}
```

The `[]byte(input)` conversion copies the string on every call. This runs once
per compiled `--allow-uri` pattern per URI SAN per handshake. Use
`rm.pattern.MatchString(input)`, which is the zero-copy equivalent.

---

## 7. `intersectsURI` re-serializes each URI SAN for every matcher

**Impact: Low**, **Effort: trivial.**

`auth/auth.go:221-230`:

```go
for _, l := range left {
    for _, r := range right {
        if l.Matches(r.String()) {
```

`url.URL.String()` builds a new string each time and is called once per
(matcher × SAN) pair, though the SAN's string form never changes. Hoist the
serialization: build `[]string` from `right` once, then run the matchers. With
finding #6 this makes ACL URI matching allocation-free per handshake (modulo
the one string per SAN).

---

## 8. `peerCertificatesString` copies `ConnectionState` twice

**Impact: Low**, **Effort: trivial.**

`proxy/str.go:42-52`:

```go
if tlsConn, ok := conn.(*tls.Conn); ok {
    if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
        return tlsConn.ConnectionState().PeerCertificates[0].Subject.String()
```

`tls.Conn.ConnectionState()` copies a large struct under a lock; this calls it
twice, and `logConnectionMessage` (`proxy/proxy.go:551-566`) invokes the
helper for both ends of the pipe on both the "opening" and "closed" log lines
— up to 8 state copies plus 4 `Subject.String()` (RDN re-serialization) per
connection when connection logging is enabled (the default). Call
`ConnectionState()` once and reuse it; optionally compute the subject strings
once per connection instead of once per log line.

---

## 9. Miscellaneous / situational notes

Items reviewed and judged low priority, recorded for completeness:

- **ACL membership checks are linear scans** (`auth/auth.go:93-115` via
  `slices.Contains`/`intersects`). Fine for the typical handful of
  `--allow-cn`/`--allow-ou` flags; if very large ACLs become a use case, CN/OU
  and DNS sets could be `map[string]struct{}` built once at startup.
- **Keystore reload does a decode→re-encode PEM round trip with nested
  appends** (`certloader/keystore.go:69-92`, `certloader/decode.go`): every
  block is re-encoded with `pem.EncodeToMemory` and concatenated with
  repeated `append`, then re-parsed by `tls.X509KeyPair`. Cold path (startup
  and `--timed-reload` ticks only) — not worth optimizing for speed, though a
  `bytes.Buffer` would tidy the allocation pattern.
- **Copy buffer size** (`proxy/proxy.go:265-270`): 32 KiB pooled buffers are a
  sensible default (TLS records max out at 16 KiB payload, so the read side of
  a `tls.Conn` rarely fills more than one record per `Read`). If throughput
  tuning is ever needed, the plaintext side could use a larger buffer to batch
  TLS record writes; making the size a hidden flag would allow experimentation
  without a rebuild. `proxy/benchmark_test.go` already provides the harness
  for measuring this.
- **Single accept goroutine** (`proxy/proxy.go:315-416`): accepts are cheap
  (handshakes happen in per-connection goroutines), so one accept loop is
  unlikely to be the bottleneck. If it ever is, the existing SO_REUSEPORT
  support (`socket/net.go`) already permits multiple listeners/accept loops.
- **go-metrics counters/timers on the connection path**
  (`proxy/proxy.go:51-59`): `connTimer` uses a locked exponentially-decaying
  sample; at extreme connection rates this lock is shared across all
  connection goroutines. Only worth revisiting if profiles show contention;
  the eventual fix is native Prometheus instruments (which also subsumes
  finding #5's bridge).
- **`fuse`/`copyData` structure** (`proxy/proxy.go:455-548`): two goroutines
  and an unbuffered channel per connection is idiomatic and hard to beat
  without platform-specific splice work, which TLS-in-userspace rules out
  anyway. The existing `struct{ io.Writer }` wrapping (to keep the pooled
  buffer in use) is correct and well-commented.

## Suggested next steps

1. Delete the `GOMAXPROCS` line (#3) and fix the metrics intervals (#5) — 
   two-line changes with immediate benefit.
2. Apply the micro-fixes (#6, #7, #8) — mechanical, low-risk.
3. Design the config-caching change (#2) as the foundation, then enable
   session resumption (#1) with ACL enforcement moved to `VerifyConnection`,
   guarded by integration tests asserting both `DidResume` on reconnect *and*
   that ACL changes still take effect after reload (ticket invalidation).
4. For `--allow-policy` users, measure OPA input-conversion cost with
   `--enable-pprof` under handshake load before deciding on #4's input
   slimming vs. decision caching.

*Analysis performed against commit `27f9125` (master).*
