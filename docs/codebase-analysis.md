# Ghostunnel Codebase Analysis

*Analysis date: 2026-07-01, at commit `27f9125`.*

This report covers the core proxy code (root package, `proxy/`, `socket/`), the
security-sensitive packages (`certloader/`, `auth/`, `policy/`, `wildcard/`,
`certstore/`), and the build/test/CI/dependency infrastructure. Findings are
grouped by theme and ordered by impact within each section. Every finding was
verified against the current source; a list of things that were checked and
found solid is included at the end.

## Summary of top priorities

1. **Hot-reload race in certloader** can permanently pair a certificate with
   the wrong trust store (`certloader/certificate.go`).
2. **PKCS#11 reload reuses the old HSM key handle** even after key rotation,
   breaking handshakes until restart (`certloader/pkcs11_enabled.go`).
3. **SPIFFE client mode with an empty ACL fails open** to any SVID
   (`auth/auth.go` + `certloader/spiffe_tls_config.go`).
4. **`runtime.GOMAXPROCS(runtime.NumCPU())` defeats Go 1.25's container-aware
   scheduler** (`main.go`).
5. **Prerelease tags publish the `latest` Docker tag** (`magefile.go` +
   `.github/workflows/docker.yml`).
6. **No vulnerability scanning (govulncheck) in CI** for a security-critical
   TLS proxy.

---

## 1. Correctness and reliability

### 1.1 [High] Concurrent `Reload()` can permanently pair a certificate with the wrong trust store

- **Where:** `certloader/certificate.go:27-30` (two independent
  `atomic.Pointer` fields); the two-step store is repeated in
  `certloader/keystore.go:99-100`, `certloader/pkcs11_enabled.go:100-101`, and
  `certloader/certstore_enabled.go:173-174`.
- **What:** `Reload()` publishes `cachedCertificate` and `cachedCertPool` as
  two separate atomic stores with no mutex. Concurrent reloads are reachable in
  production: the signal handler goroutine (`signals.go:94`) and the
  `--timed-reload` ticker goroutine (`signals.go:103-105`) both call
  `env.reload()` → `tlsConfigSource.Reload()`.
- **Why it matters:** If reload A and reload B interleave (A stores cert, B
  stores cert+pool, A stores pool), the process is left *persistently* serving
  cert-from-B validated against CA-pool-from-A — not just a transient window.
  When a leaf and its CA are rotated together, this can silently break or
  (worse) loosen client-cert validation until the next reload. There is also a
  milder per-connection tear: `certtlsconfig.go:70-75` snapshots `ClientCAs` at
  accept time while `GetCertificate` reads the cert at handshake time.
- **Fix:** Replace the two pointers with a single
  `atomic.Pointer[struct{ cert *tls.Certificate; pool *x509.CertPool }]`
  published in one store, and serialize `Reload()` with a `sync.Mutex`. This
  also deduplicates the identical publish sequence across the three backends.

### 1.2 [High] PKCS#11 reload reuses the cached HSM key handle even when the key was rotated

- **Where:** `certloader/pkcs11_enabled.go:83-93`.
- **What:** On reload, if a cached certificate exists, the old `PrivateKey` (a
  `pkcs11key` handle bound to the *old* public key) is unconditionally attached
  to the newly read certificate. There is no check that `certs[0].PublicKey`
  still matches the cached key.
- **Why it matters:** The normal HSM rotation flow (generate new key in token,
  install new cert file, SIGUSR1) yields a cert/key mismatch: `Reload()`
  reports success and logs "re-using previously cached private key handle", but
  every subsequent handshake fails with signature errors until process restart.
  It fails at the worst time (rotation) with a misleading log trail.
- **Fix:** Compare the new leaf's public key against the previous leaf's (e.g.
  via `interface{ Equal(crypto.PublicKey) bool }`) and call `pkcs11key.New`
  again when they differ, destroying the old handle.

### 1.3 [Medium] Timed reload races with shutdown: status flips back to "ok"/READY while draining

- **Where:** `signals.go:99-106`, `status.go:99-106`.
- **What:** `reloadHandler` runs `for range time.Tick(interval)` forever with no
  stop mechanism. `env.reload()` ends with `env.status.Listening()`, which sets
  `listening = true` and sends `READY=1` to systemd. If a timed reload fires
  after `Stopping()` during the (up to 5-minute) graceful drain, `/_status`
  reports `ok: true` again and systemd receives `READY=1` *after* `STOPPING=1`.
- **Why it matters:** Load balancers polling `/_status` will re-add an instance
  that is mid-shutdown and no longer accepting connections (listener already
  closed), sending traffic to a dead port.
- **Fix:** (a) Make `statusHandler.Listening()` a no-op when `stopping` is set
  (one-line guard under the existing mutex), and (b) give `reloadHandler` a
  stop signal (context/channel closed in `shutdownFunc`) and replace
  `time.Tick` with a `time.Ticker` + `select`.

### 1.4 [Medium] `Proxy.Shutdown` is not safe for concurrent callers

- **Where:** `proxy/proxy.go:288-296`.
- **What:** `Shutdown()` guards re-entry with
  `if p.context.Err() != nil { return }` and then calls
  `p.cancel(); p.Listener.Close(); p.handlers.Done()`. Two *concurrent* callers
  can both observe `Err() == nil` and both call `handlers.Done()`, driving the
  WaitGroup counter negative → `panic: sync: negative WaitGroup counter`. The
  existing test (`proxy_test.go:316-318`) only exercises *sequential* triple
  shutdown.
- **Why it matters:** `Shutdown` is exported API of the proxy package. Inside
  ghostunnel it happens to be called from a single goroutine, so this is
  latent — but it is one diff away from a crash for any embedder or a future
  second call site (e.g. the Windows service stop path).
- **Fix:** Wrap the body in a `sync.Once`:
  `p.shutdownOnce.Do(func() { p.cancel(); p.Listener.Close(); p.handlers.Done() })`.

### 1.5 [Medium] Keychain `Reload()` never closes the store or any identities (resource leak)

- **Where:** `certloader/certstore_enabled.go:80-176`.
- **What:** `certstore.Store.Close()` and `Identity.Close()` exist precisely to
  release CGO-managed resources (`certstore/certstore.go:36,54`; on Windows
  `CertCloseStore`/`CertFreeCertificateContext`/NCrypt key handles at
  `certstore_windows.go:254-262,353-363`; on macOS `newMacIdentity` *retains*
  every `SecIdentityRef`, `certstore_darwin.go:76-84`). `Reload()` never calls
  either — not for non-selected candidates, not for the previously active
  identity when replaced.
- **Why it matters:** With `--timed-reload` this leaks CF objects / cert
  contexts / key handles on every tick, unbounded, on both platforms where this
  backend exists.
- **Fix:** `defer store.Close()` where safe; `Close()` every identity except
  the chosen one; track the previously chosen identity and close it on the
  next successful reload (once in-flight handshakes can no longer hold its
  signer). Add close-tracking assertions to the existing fake-store harness in
  `certloader/certstore_reload_test.go`, which already has the `openStore`
  injection seam.

### 1.6 [Medium] Graphite reporter hardcodes a 1-second flush interval, ignoring `--metrics-interval`

- **Where:** `main.go:600`.
- **What:** `go graphite.Graphite(metrics.DefaultRegistry, 1*time.Second, ...)`
  — but the `--metrics-interval` flag (`main.go:148`) documents "Collect (and
  post/send) metrics every specified interval" and is honored only by the
  sqmetrics URL reporter (`main.go:626`).
- **Why it matters:** Flag contract violation; flushing the full registry over
  raw TCP every second is aggressive for most Graphite deployments and cannot
  be tuned down.
- **Fix:** Pass `*metricsInterval` as the second argument.

### 1.7 [Low] Every graceful shutdown with `--status` logs a spurious error

- **Where:** `main.go:962-967`.
- **What:** The `serveStatus` goroutine logs any non-nil error from
  `statusHTTP.Serve(listener)`. On shutdown, the signal handler calls
  `statusHTTP.Shutdown()` (`signals.go:53`), which makes `Serve` return
  `http.ErrServerClosed`, so every clean shutdown prints
  `error serving status port: http: Server closed`.
- **Fix:** `if err != nil && !errors.Is(err, http.ErrServerClosed) { ... }`.

### 1.8 [Low] Status listener leaked on TLS-config error paths in `serveStatus`

- **Where:** `main.go:934-951`.
- **What:** The listener opened at `main.go:934` is not closed if
  `buildServerConfig` or `getServerConfig` fails before `http.Server.Serve`
  takes ownership.
- **Why it matters:** Low practical impact (the process exits shortly after),
  but for a `unix:` status socket the `SetUnlinkOnClose` cleanup never runs,
  leaving a stale socket file that can break the next start.
- **Fix:** Close the listener in both error branches, matching the pattern
  already used in `serverListen`/`clientListen`.

### 1.9 [Low] Windows service startup deadline contradicts its own progress-tick design

- **Where:** `windows_service.go:44,188`.
- **What:** `Execute` ticks `StartPending` checkpoints every 5 seconds
  explicitly so the SCM tolerates slow startup (e.g. PKCS#11/HSM probing), but
  then aborts startup itself via a 30-second `startDeadline` — the same value
  as the SCM default the ticks are meant to outlive.
- **Why it matters:** The checkpoint mechanism buys nothing: any startup slower
  than 30 seconds fails anyway, just with a ghostunnel-generated error instead
  of an SCM kill. Slow HSM/network-cert-source startups will flap.
- **Fix:** Use a separate, longer startup timeout constant (2–5 minutes) — the
  checkpoint ticker already keeps the SCM satisfied — or make it configurable.

### 1.10 [Low] Keychain candidate sort re-fetches chains in the comparator and is inconsistent on errors

- **Where:** `certloader/certstore_enabled.go:136-148`.
- **What:** The `sort.Slice` comparator calls `CertificateChain()` (a CGO call
  on both platforms) O(n log n) times, and when both sides error it returns
  `true` for both `less(i,j)` and `less(j,i)` — an inconsistent ordering, so
  the "newest NotAfter" selection can be arbitrary.
- **Fix:** Materialize `(identity, chain)` pairs once during the filter loop
  (the chain was already fetched there) and sort those; drop candidates whose
  chain fetch errored.

---

## 2. Security hardening

### 2.1 [High] SPIFFE client mode with an empty ACL fails open to any SVID

- **Where:** `auth/auth.go:141-150` in combination with
  `certloader/spiffe_tls_config.go:100-101` and `main.go:496-510`.
- **What:** `VerifyPeerCertificateClient` returns nil for an empty ACL,
  explicitly assuming "DNS name verification has already taken place"
  (`auth.go:139-140`). But in Workload-API mode the SPIFFE config sets
  `InsecureSkipVerify = true` and wraps verification with `AuthorizeAny()`, so
  no hostname verification ever happens — and `clientValidateFlags()` does not
  require any `--verify-*` flag.
- **Why it matters:** A ghostunnel client using `--use-workload-api` without
  `--verify-uri` will accept a connection to *any* workload whose SVID chains
  to the trust bundle — much weaker than the non-SPIFFE default (hostname
  pinning), and the fail-open comment's premise is false on this path.
- **Fix:** Require at least one `--verify-*` flag (or an explicit
  `--verify-any`) when `--use-workload-api` is set in client mode;
  alternatively pass a real authorizer (e.g. `tlsconfig.AuthorizeMemberOf`)
  instead of `AuthorizeAny()` when the ACL is empty.

### 2.2 [Medium] Server-side client-cert verification silently falls back to the system trust store

- **Where:** `certloader/loader.go:80-83` (`LoadTrustStore("")` →
  `x509.SystemCertPool()`), used as `ClientCAs` via `certtlsconfig.go:73`.
- **What:** When `--cacert` is unset (it is optional, `main.go:127`), the
  *server's* `ClientCAs` becomes the entire WebPKI system pool.
- **Why it matters:** With `--allow-all`, anyone holding any publicly-trusted
  certificate authenticates; with `--allow-dns x`, anyone who can obtain a
  WebPKI cert for a matching name they control does. The system pool is a
  sensible default for *client* `RootCAs`, but for server mTLS it is an easy
  foot-gun.
- **Fix:** Log a prominent startup warning (or require explicit opt-in) when
  server mode verifies client certs against the system pool, especially in
  combination with `--allow-all`.

### 2.3 [Medium] Wildcard URI matching runs the glob over a re-serialized URL with only `/` as separator

- **Where:** `auth/auth.go:221-230` (`l.Matches(r.String())`) and
  `wildcard/matcher.go:154-158` (`*` → `[^/]+`).
- **What:** URI SANs are matched by stringifying `*url.URL` and running the
  glob. Because `?`, `#`, `@`, `:` and percent-encoded `/` (`%2F`) are not
  separators, `--allow-uri scheme://host/x/*` also matches
  `scheme://host/x/y?z`, `scheme://host/x/y#z`, and `scheme://host/x/a%2Fb`;
  `*` in the authority position matches `user@host:port` as one token.
  `url.URL.String()` re-serialization may also diverge from the raw SAN bytes
  for unusual encodings.
- **Why it matters:** For SPIFFE IDs (no query/fragment allowed) this is mostly
  moot, but `--allow-uri`/`--verify-uri` accept arbitrary URI SANs; a CA that
  signs URIs with query strings or encoded path segments can produce certs
  that over-match operator intent. This is an ACL, so over-matching is a
  privilege grant.
- **Fix:** In `intersectsURI`, reject (fail closed on) URIs containing
  `RawQuery`/`Fragment`/`User` or percent-encoded separators before matching —
  or match structurally (scheme, host, decoded path segments) instead of
  against the flattened string. Add auth tests for these inputs (none exist
  today; `auth_test.go` only covers plain `scheme://path/...` URIs).

### 2.4 [Medium] No vulnerability scanning in CI

- **Where:** `.github/workflows/` — no reference to `govulncheck` or `gosec`
  anywhere.
- **What:** A security-critical TLS proxy with a large dependency surface (OPA,
  certmagic, grpc, x/crypto, go-jose) has no automated vulnerability check.
- **Why it matters:** Known CVEs in dependencies (historically frequent in
  x/net, x/crypto, grpc, go-jose) are only caught by monthly dependabot bumps,
  not by CI on the code paths actually in use.
- **Fix:** Add a `govulncheck ./...` step to `lint.yml` or a scheduled
  workflow.

### 2.5 [Medium] Release artifacts are unsigned and unattested

- **Where:** `.github/workflows/release.yml:141-160`, `magefile.go:261-300`
  (`Github.Publish` uploads `dist/ghostunnel-*` as-is).
- **What:** The release pipeline uploads bare binaries; there is no
  `SHA256SUMS` file, no artifact attestation, and no cosign/GPG signature
  (macOS binaries are codesigned, but Linux/Windows have nothing).
- **Why it matters:** Downstream users and packagers have no way to verify
  binary integrity or provenance for a security tool.
- **Fix:** Generate `dist/SHA256SUMS` in `Github.Publish` and include it in the
  release assets; add `actions/attest-build-provenance` (needs
  `id-token: write`, `attestations: write`) to the release workflow.

### 2.6 [Medium] Prerelease tags (e.g. `v1.11.0-rc.1`) publish the `latest` Docker tag

- **Where:** `magefile.go:1056-1059` (`getDockerTags` returns
  `[]string{tag, "latest"}` for any `refs/tags/*`), triggered by
  `.github/workflows/docker.yml` (`tags: [ 'v*.*.*' ]`).
- **What:** GitHub's glob `v*.*.*` matches `v1.11.0-rc.1`, and `getDockerTags`
  unconditionally adds `latest` for tag refs — so an RC push publishes
  `ghostunnel/ghostunnel:latest` pointing at prerelease code.
- **Why it matters:** Users pulling `:latest` silently get release candidates.
- **Fix:** Skip `latest` for prerelease tags:
  `if !strings.Contains(tag, "-") { tags = append(tags, "latest") }` (and/or
  tighten the workflow trigger to exclude `-rc` tags).

---

## 3. Performance and modernization

### 3.1 [High] `runtime.GOMAXPROCS(runtime.NumCPU())` defeats Go 1.25's container-aware scheduler

- **Where:** `main.go:553`.
- **What:** `run()` unconditionally pins GOMAXPROCS to the host CPU count. This
  was a no-op since Go 1.5, but as of Go 1.25 (which this project targets) it
  is actively harmful: Go 1.25 defaults GOMAXPROCS to the container's cgroup
  CPU limit and *dynamically updates* it; the explicit call opts out of both.
- **Why it matters:** Ghostunnel ships as a Docker image. A container limited
  to 2 CPUs on a 64-core host will run with GOMAXPROCS=64 — CFS throttling and
  GC latency spikes in the proxy hot path. Ironically, `landlock_linux.go:46`
  already grants `/sys` read access specifically so the runtime can read cgroup
  info for GOMAXPROCS.
- **Fix:** Delete the line.

### 3.2 [Medium] `isClosedConnectionError` relies on error-string matching instead of sentinel errors

- **Where:** `proxy/proxy.go:579-586`.
- **What:** Hot-path close detection matches
  `strings.Contains(err.Error(), "closed network connection")` and
  `"closed pipe"`, plus an `OpError.Op` allowlist. Go 1.16+ provides
  `net.ErrClosed` exactly for this, and crypto/tls and internal/poll wrap it.
- **Why it matters:** String matching is fragile against stdlib wording or
  wrapping changes, and misses custom `net.Conn` implementations that correctly
  return `net.ErrClosed` with different text. This function decides whether an
  error is logged on *every* connection teardown.
- **Fix:**
  `return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)`.
  The `Op` allowlist is unnecessary — the function is only called from
  `copyData`, never on accept errors.

### 3.3 [Low] HTTP backend health check never drains the response body, defeating keep-alive

- **Where:** `status.go:209-216`.
- **What:** `checkBackendStatus` does `defer resp.Body.Close()` without reading
  the body, so the connection cannot be reused and every `/_status` poll dials
  a brand-new backend connection (including a TLS handshake in client mode).
- **Fix:** `_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))` before
  close.

### 3.4 [Low] `policy/loader.go` still uses `unsafe.Pointer` + atomic functions for the cached query

- **Where:** `policy/loader.go:35-36,76,82`.
- **What:** `cachedPolicy unsafe.Pointer` with
  `atomic.StorePointer`/`LoadPointer`, while the sibling certloader code
  already uses typed `atomic.Pointer[T]`.
- **Why it matters:** `unsafe` here is needless; typed atomics remove a class
  of casting mistakes. Note `Eval` would nil-panic if called before a
  successful `Reload` — `LoadFromPath` guards this today, but the type doesn't.
- **Fix:** `cachedPolicy atomic.Pointer[rego.PreparedEvalQuery]`, plus a nil
  check in `Eval`.

---

## 4. Code quality and maintainability

### 4.1 [Medium] `serverListen` and `clientListen` are ~90% duplicated

- **Where:** `main.go:753-868`.
- **What:** Both functions do open-listener → build proxy → serveStatus
  (including identical listener-close-on-error logic) → log → `go p.Accept()` →
  `Listening()/HandleWatchdog()/signalHandler()/Wait()`. They differ only in
  the wrapped-TLS listener, ACL/config building, and proxy-protocol mode.
- **Why it matters:** The shutdown/startup sequencing (the subtlest part of
  main) must be maintained twice; the fix for finding 1.8, for instance, needs
  applying in multiple places.
- **Fix:** Extract a
  `runProxy(env *Environment, listener net.Listener, ppMode proxy.ProxyProtocolMode) error`
  helper containing everything from `proxy.New` through `p.Wait()`. This also
  makes the lifecycle unit-testable with a fake listener.

### 4.2 [Medium] `VerifyPeerCertificateServer` and `VerifyPeerCertificateClient` are ~55-line near-duplicates

- **Where:** `auth/auth.go:80-134` vs `auth/auth.go:141-196`.
- **What:** The CN/OU/DNS/IP/URI/OPA matching block is duplicated verbatim; the
  only real differences are the empty-ACL behavior (fail closed vs open) and
  `AllowAll` being honored only server-side.
- **Why it matters:** Any future check (e.g. the URI hardening in finding 2.3)
  must be applied twice; divergence here is an access-control bug by
  definition.
- **Fix:** Extract a private
  `func (a ACL) matches(cert *x509.Certificate) (bool, error)` and keep only
  the fail-open/fail-closed policy in the two public wrappers.

### 4.3 [Test coverage] PKCS#11 reload logic is untestable and untested

- **Where:** `certloader/pkcs11_enabled.go:65-104` vs
  `certloader/pkcs11_test.go` (only trivial accessor tests).
- **What:** `pkcs11key.New` is called directly, so the key-caching/rotation
  branch (finding 1.2) — the trickiest logic in the file — has zero unit
  coverage. Contrast with the keychain backend, which has an injectable
  `openStore` seam and ~500 lines of reload tests.
- **Fix:** Add an injectable
  `newPKCS11Key func(module, label, pin string, pub crypto.PublicKey) (crypto.PrivateKey, error)`
  field mirroring the `openStore` pattern, then test: first load,
  reload-same-key (handle reused), reload-new-key (handle replaced — currently
  exposes finding 1.2), and module failure keeping old state. Also add a
  `-race` test hammering `Reload()` from two goroutines against
  `GetCertificate`/`GetTrustStore` to lock in the fix for finding 1.1.

---

## 5. Build, dependencies, and CI

### 5.1 [High] golangci-lint's entire dependency tree is vendored into the repo and pollutes go.mod

- **Where:** `go.mod:281-284` (`tool` directive), `go.mod:35-277` (~240
  indirect deps), `vendor/` (83 MB total, including dozens of linter repos).
- **What:** Declaring `github.com/golangci/golangci-lint/v2` as a Go 1.24+
  `tool` in the main module means `go mod vendor` vendors the whole linter
  toolchain, and every linter becomes an indirect dependency of ghostunnel.
- **Why it matters:** Tens of MB of linter-only code ships in the repo,
  `go.mod`/`go.sum` churn from linter updates is indistinguishable from real
  dependency changes, vulnerability scanners flag linter deps as ghostunnel
  deps, and golangci-lint upstream discourages building from source. (The
  `magefile/mage` tool dependency is fine — it's tiny.)
- **Fix:** Move the golangci-lint tool declaration into a separate module
  (e.g. `tools/go.mod`, invoked as
  `go tool -modfile=tools/go.mod golangci-lint run` from `magefile.go:79`), or
  drop it and use the official `golangci/golangci-lint-action` binary install
  in `lint.yml`. Then `go mod tidy && go mod vendor` shrinks `vendor/`
  dramatically.

### 5.2 [Medium] Direct dependency on deprecated `mholt/acmez` v1 solely for one constant

- **Where:** `certloader/acmetlsconfig.go:12` (used only for
  `acmez.ACMETLS1Protocol`); `go.mod` has both `mholt/acmez v1.2.0` (direct)
  and `mholt/acmez/v3` (indirect via certmagic).
- **What:** Two major versions of acmez are in the module graph and vendor
  tree; the v1 dependency exists only for the `"acme-tls/1"` ALPN constant,
  which exists identically in v3.
- **Fix:** Change the import to `github.com/mholt/acmez/v3` in
  `acmetlsconfig.go` (and its test), then `go mod tidy && go mod vendor` to
  drop v1 entirely.

### 5.3 [Medium] Dockerfiles install mage with `go install ...@latest` instead of the pinned tool dependency

- **Where:** `Dockerfile-alpine:19`, `Dockerfile-debian:19`,
  `Dockerfile-distroless:19`, `Dockerfile-test:16`; `Dockerfile-test:15` also
  installs `golang.org/x/tools/cmd/cover@latest`.
- **What:** Image builds fetch mage at whatever version is latest at build
  time, even though mage is pinned in `go.mod`, vendored, and invocable as
  `go tool mage` (the convention used everywhere else). The `cmd/cover`
  install is dead weight — the cover tool ships with the Go distribution.
- **Why it matters:** Non-reproducible builds, an extra network fetch that
  defeats vendoring, and inconsistency with the documented build system.
- **Fix:** Replace the `go install`/`export PATH`/`mage` sequence with
  `go tool mage -v go:build` in all four Dockerfiles; delete the
  `cover@latest` install. Also consider pinning base images to a minor version
  (`golang:1.25-alpine`), since dependabot only tracks the gomod and
  github-actions ecosystems, not docker.

### 5.4 [Medium] CI builds with `go-version: stable` and `cache: false` in every workflow

- **Where:** `.github/workflows/test.yml:26-28`, `lint.yml:18-21`,
  `compile.yml`, `release.yml`, `docker.yml`, `website.yml`.
- **What:** CI ignores the version pinned in `go.mod` (1.25.1) and disables the
  setup-go build cache in all 10+ jobs.
- **Why it matters:** `stable` drifts independently of `go.mod` — releases are
  built with whatever Go is newest that day, hurting reproducibility and
  occasionally breaking when `go.mod` is bumped ahead of the runner. With cgo
  builds and a full test matrix, disabling the build cache measurably slows
  every run (the module cache is moot due to vendoring; the *build* cache is
  not).
- **Fix:** Use `go-version-file: go.mod` and drop `cache: false`.

### 5.5 [Medium] CodeQL config exists but there is no CodeQL workflow

- **Where:** `.github/codeql/codeql-config.yml` (comment references a
  `codeql.yml` that doesn't exist in `.github/workflows/`).
- **What:** Custom config files under `.github/codeql/` are only honored by
  *advanced setup* (a workflow), not default setup — so either CodeQL isn't
  running at all, or it runs via default setup while silently ignoring the
  `paths-ignore` config.
- **Fix:** Restore a `codeql.yml` workflow (with
  `config-file: .github/codeql/codeql-config.yml`), or delete the stale config
  if default setup is intentional.

### 5.6 [Low] Linter config is minimal for a security-focused codebase; `go fmt` is requested but never enforced

- **Where:** `.golangci.yml:5` (`default: standard` — only
  errcheck/govet/ineffassign/staticcheck/unused); CLAUDE.md/CONTRIBUTING ask
  contributors to format with `go fmt` but no CI step checks it.
- **Fix:** Enable `gosec`, `errorlint`, `bodyclose`, and `misspell` in
  `.golangci.yml` (triaging initial findings with targeted exclusions) and add
  a `formatters: gofmt` section so `go tool mage go:lint` enforces formatting.

### 5.7 [Low] Unmaintained metrics dependency stack

- **Where:** `go.mod` — `cyberdelia/go-metrics-graphite` (last commit 2016),
  `deathowl/go-metrics-prometheus` (2022), `rcrowley/go-metrics`
  (self-described stagnant), `square/go-sq-metrics` (2017).
- **What:** Four metrics libraries, three effectively abandoned, bridged into
  Prometheus via a third-party shim.
- **Fix:** Longer-term, migrate internal instrumentation to
  `prometheus/client_golang` directly (already a direct dependency), keeping
  the Graphite bridge only if users depend on it. No urgent action — flagging
  that dependabot can never help here.

---

## Verified non-findings

The following were explicitly checked and found solid (no action needed):

- The ACME TLS-ALPN-01 `GetConfigForClient` relax path
  (`certloader/acmetlsconfig.go:271-283`) is correctly gated and backstopped by
  `proxy/proxy.go:428` dropping `acme-tls/1` connections before forwarding.
- go-spiffe's `WrapVerifyPeerCertificate` passes SPIFFE-verified chains to the
  ACL callback, so server-side SPIFFE + ACL fails closed.
- `wildcard` pattern compilation anchors and quotes correctly (including the
  `**` and trailing-separator special cases) and has strong test coverage.
- The proxy `Accept` semaphore accounting is correct on all error paths; the
  PROXY-protocol TLV construction and Unix-addr handling are correct;
  `copyData`'s pooled 32 KiB buffers and `WriteTo`/`ReadFrom` hiding are the
  right hot-path pattern.
- `tests/common.py` port allocation is robust (SO_REUSEPORT co-bind
  reservations held for process lifetime); raw `time.sleep` occurrences in
  integration tests are bounded poll loops, not fixed waits.
- Coverage merging in `magefile.go` (`GOCOVERDIR` signal-safe flushing,
  `go tool covdata` conversion) is correctly wired.
