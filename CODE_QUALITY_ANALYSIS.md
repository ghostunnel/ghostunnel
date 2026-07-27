# Ghostunnel Code Quality Analysis

Comprehensive analysis focused on bugs and inconsistencies.

- **Scope:** all 11 Go packages (~12k lines of production Go), the 137-test Python
  integration suite, the lint configuration, and the CI build/test matrix.
- **Baseline commit:** `1673906` (`master`), analyzed on branch
  `claude/code-quality-analysis-plan-6pm5xl`.
- **Toolchain:** Go 1.25.1, golangci-lint 2.12.2.

## Executive summary

The codebase is in good shape. `go vet` is clean, the project lint config reports
0 issues, `go test -race ./...` passes, and statement coverage is **95.5%** with
only ten functions below 80% (nearly all platform stubs). The comments are
unusually load-bearing — many of them document a real hazard and the reasoning
that resolved it — and several things that looked like bugs on first read turned
out to be deliberate and correctly reasoned.

Four defects survived verification. The most significant is that
`--max-conn-lifetime` does not actually bound connection lifetime once either
side half-closes, which is reproducible and contradicts the flag's documented
"no matter what" guarantee.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | `--max-conn-lifetime` defeated by a half-close | High | Confirmed with repro |
| 2 | `--shutdown-timeout=0` force-exits instead of draining | Medium | Confirmed empirically |
| 3 | Force-exit timer races normal exit → nondeterministic exit code | Medium | Confirmed empirically |
| 4 | `certstore_windows_test.go` build tags break windows/nocgo test build | Medium | Confirmed |
| 5 | `keystore.Reload` torn read between certificate and trust store | Low | Confirmed by inspection |
| 6 | `err == io.EOF` outlier in `modutf8.go` | Low | Confirmed |
| 7 | `**` does not match strings containing newlines | Low | Confirmed with repro |
| 8 | Redundant `resp.Ok && resp.BackendOk` in status handler | Low | Confirmed |
| 9 | Status HTTP check does not drain response body | Low | Confirmed |

---

## Confirmed findings

### 1. `--max-conn-lifetime` is defeated by a half-close — High

**Location:** `proxy/proxy.go:608-613` (vs. `proxy/proxy.go:567-570`)

`fuse` establishes the lifetime bound by setting a deadline on both connections:

```go
if p.MaxConnLifetime > 0 {
    setDeadline(client, p.MaxConnLifetime)
    setDeadline(backend, p.MaxConnLifetime)
}
```

But `copyData`'s defer unconditionally **overwrites** that deadline when either
direction finishes:

```go
defer func() {
    closeRead(src)
    closeWrite(dst)
    setDeadline(src, p.CloseTimeout)   // <-- resets the MaxConnLifetime deadline
    setDeadline(dst, p.CloseTimeout)
}()
```

`setDeadline` calls `conn.SetDeadline(time.Now().Add(timeout))`, which is
absolute, not a minimum. As soon as one direction returns — which a client can
trigger at will by half-closing its write side immediately after connecting —
the deadline is pushed out to `now + CloseTimeout`, discarding the lifetime
bound entirely.

**Failure scenario.** With `--max-conn-lifetime=1s --close-timeout=60s` (60s is
the default), a client connects, sends nothing, and calls `CloseWrite()`. The
`copyData(backend, client)` direction sees EOF immediately and runs its defer,
resetting both deadlines to `now + 60s`. The connection survives ~60 seconds
instead of 1. Repeat to hold connections open well past the configured limit —
the exact resource-exhaustion case the flag exists to prevent.

The flag help is unambiguous about the intended guarantee:

> `--max-conn-lifetime` — "Maximum lifetime for connections post handshake, **no matter what**. Zero means infinite."

**Verification.** Reproduced with `maxConnLifetime=1s, closeTimeout=6s`:

```
connection torn down after 6.001292647s (maxConnLifetime=1s, closeTimeout=6s)
```

Repro (drop into `proxy/`, `go test -run TestVerifyMaxConnLifetimeVsHalfClose ./proxy/`):

```go
func TestVerifyMaxConnLifetimeVsHalfClose(t *testing.T) {
	backendListener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendListener.Close()
	go func() {
		for {
			c, err := backendListener.Accept()
			if err != nil {
				return
			}
			_ = c // hold it open, never write
		}
	}()

	frontListener, _ := net.Listen("tcp", "127.0.0.1:0")
	dial := func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", backendListener.Addr().String())
	}

	// connectTimeout=5s, closeTimeout=6s, maxConnLifetime=1s
	p := New(frontListener, 5*time.Second, 6*time.Second, 1*time.Second, 0,
		dial, &testLogger{}, 0, ProxyProtocolOff, NilMetrics())
	go p.Accept()
	defer p.Shutdown()

	conn, _ := net.Dial("tcp", frontListener.Addr().String())
	defer conn.Close()

	// Half-close the write side: copyData(backend, client) returns immediately
	// and runs its deadline-resetting defer.
	conn.(*net.TCPConn).CloseWrite()

	start := time.Now()
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	conn.Read(buf) // blocks until the proxy tears the connection down
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("connection lived %v, exceeding --max-conn-lifetime=1s", elapsed)
	}
}
```

**Why the existing tests miss it.** Both `tests/test-server-max-conn-lifetime.py`
and `tests/test-server-idle-reaper.py` hold connections *fully* open and idle.
Neither half-closes, so neither reaches the defer that resets the deadline.

**Suggested fix.** Clamp rather than overwrite — track the absolute lifetime
deadline once in `fuse` and have `copyData` set `min(lifetimeDeadline, now+CloseTimeout)`.
Any fix should come with an integration test that exercises the half-close path.

---

### 2. `--shutdown-timeout=0` force-exits immediately instead of draining — Medium

**Location:** `signals.go:65-70`, flag defined at `main.go:141`

```go
time.AfterFunc(env.shutdownTimeout, func() {
    logger.Printf("graceful shutdown timeout: forcing exit")
    exitFunc(1)
})
```

`time.AfterFunc(0, ...)` fires essentially immediately, so `--shutdown-timeout=0`
means "abandon every in-flight connection and exit non-zero on the first
SIGTERM." The flag help — "Process shutdown timeout. Terminates after timeout
even if connections still open." — does not document zero, and the value is
never validated.

This is inconsistent with how the codebase treats every other duration flag:

| Flag | Zero semantics | Validated? |
|------|---------------|-----------|
| `--connect-timeout` | rejected | Yes — `main.go:276` |
| `--use-workload-api-timeout` | "wait indefinitely" | Yes — `main.go:279` |
| `--max-conn-lifetime` | "Zero means infinite" | Documented |
| `--close-timeout` | "Zero means immediate closure" | Documented |
| **`--shutdown-timeout`** | **undocumented; means "exit now"** | **No** |

A user reading the table above would reasonably expect `0` to mean "wait
forever" (as with `--max-conn-lifetime` and `--use-workload-api-timeout`). It
means the opposite.

**Verification.** Observed directly:

```
17:01:30.543094 received terminated, shutting down
17:01:30.543436 shutdown proxy, waiting for drain
17:01:30.543376 graceful shutdown timeout: forcing exit
```

**Suggested fix.** Either reject `0` in `validateFlags` alongside
`--connect-timeout`, or define `0` as "no timeout" (skip arming the timer) and
document it.

---

### 3. Force-exit timer races the normal exit path — Medium

**Location:** `signals.go:65-70`

The `time.AfterFunc` force-exit timer is never stopped after a successful drain.
When drain completes near the timeout boundary, two exit paths race:
`exitFunc(1)` from the timer, and `exitFunc(0)` from `main` after `run()`
returns. The winner is nondeterministic.

**Failure scenario.** A supervisor (systemd, Kubernetes) that distinguishes
clean from failed shutdown sees a spurious failure whenever drain and timeout
finish together. Restart backoff, alerting, and rolling-update logic keyed on
exit status become flaky.

**Verification.** Five identical runs, SIGTERM with no in-flight connections:

```
run 1 exit code: 0
run 2 exit code: 1
run 3 exit code: 1
run 4 exit code: 1
run 5 exit code: 1
```

Same binary, same flags, same signal — different exit codes. (This run used
`--shutdown-timeout=0` to make the window wide and reliably observable; the
race is inherent to the unstopped timer and exists at any timeout value,
just with a much narrower window.)

**Suggested fix.** Retain the `*time.Timer` from `AfterFunc` and `Stop()` it
once `p.Wait()` returns, before the normal exit path runs.

---

### 4. `certstore_windows_test.go` build tags break the windows/nocgo test build — Medium

**Location:** `certstore/certstore_windows_test.go:1`

```
$ GOOS=windows CGO_ENABLED=0 go vet ./...
vet: certstore/certstore_windows_test.go:16:16: undefined: NTE_BAD_ALGID
```

`certstore_windows.go` uses `import "C"`, so Go implicitly excludes it when
`CGO_ENABLED=0`; `certstore_other.go` (`//go:build !cgo || (!darwin && !windows)`)
takes over. But the test file is tagged only `//go:build windows`, so it still
builds and references `NTE_BAD_ALGID`, which lives in the now-excluded cgo file.

This is an internal inconsistency: the sibling `certstore_test.go` gets it right
with `//go:build cgo && (darwin || windows)`.

**Failure scenario.** `CGO_ENABLED=0 go test ./...` and `go vet ./...` fail to
compile on Windows. Anyone building a pure-Go Windows binary — a reasonable
thing to want, since `certstore_other.go` exists precisely to support it —
cannot run or vet the test suite.

CI does not catch this: `test.yml` runs `mage test:all` on `windows-latest`,
where cgo is enabled by default.

**Suggested fix.** Change the tag to `//go:build windows && cgo`, and add a
`GOOS=windows CGO_ENABLED=0 go vet ./...` step to the compile workflow.

---

### 5. `keystore.Reload` torn read between certificate and trust store — Low

**Location:** `certloader/keystore.go:98-99`

```go
c.cachedCertificate.Store(&certAndKey)
c.cachedCertPool.Store(bundle)
```

Two independent atomic stores, not one atomic swap. A handshake landing between
them sees the new leaf certificate paired with the old CA bundle.

Compounding this, `certTLSConfig.GetServerConfig` (`certloader/certtlsconfig.go:100`)
caches the built `tls.Config` keyed on the trust-store *pointer* while resolving
the certificate through a callback at handshake time — so the two values are
inherently read at different moments.

**Failure scenario.** During a rotation that changes both the CA and the leaf,
a server can briefly present the new certificate while still validating clients
against the old CA bundle. This fails closed (new clients are rejected, not
wrongly accepted), so it is an availability blip rather than a security hole,
and it self-heals on the next config fetch.

Worth noting alongside this: `env.reload()` can run concurrently from two
goroutines — the signal handler (`signals.go:101`, on SIGHUP) and the timed
reload handler (`main.go:842`) — and no `Reload()` implementation takes a lock.
Concurrent reloads read the same files, so in practice they converge, but
nothing in the design enforces that.

**Suggested fix.** Store one immutable struct holding both values behind a
single `atomic.Pointer`.

---

### 6. `err == io.EOF` outlier — Low

**Location:** `certloader/jceks/modutf8.go:121`

The same file uses `errors.Is(err, io.EOF)` at lines 51, 73, and 100, then
switches to `==` at line 121. This is the **only** direct error comparison left
in the production tree — everything else uses `errors.Is`/`errors.As`.

Behaviorally equivalent today, since `bufio.Reader.ReadByte` returns a bare
`io.EOF`. It is a pure consistency defect, and the kind that becomes a real bug
if the reader is ever wrapped.

---

### 7. `**` does not match strings containing newlines — Low

**Location:** `wildcard/matcher.go:130`, `wildcard/matcher.go:167`

The package doc states a `**` wildcard "will match anything, including the
separator rune," and a bare `**` is compiled to `^.*$`. In Go's `regexp`, `.`
does not match `\n`, so `**` rejects any input containing a newline.

**Verification.**

```
pattern="**"              input="spiffe://foo/bar"         matches=true
pattern="**"              input="spiffe://foo/bar\nevil"   matches=false
pattern="spiffe://foo/**" input="spiffe://foo/bar\nevil"   matches=false
pattern="spiffe://foo/*"  input="spiffe://foo/bar\nevil"   matches=true
```

**This is not a security hole** — it fails *closed*, denying access rather than
granting it. I specifically checked for the dangerous direction (a newline
smuggling a URI SAN past a restrictive pattern) and found none: Go's `$` anchors
at end-of-text with no trailing-newline exception, and the single-`*` case
(`[^/]+`, which does match `\n`) stays correctly confined within one segment.

The defect is that documented behavior and actual behavior disagree, and that
`*` and `**` treat newlines differently. Fix by compiling with `(?s)` or by
documenting the exclusion.

---

### 8. Redundant condition in status handler — Low

**Location:** `status.go:193`

```go
resp.Ok = s.listening && resp.BackendOk   // line 181
...
if resp.Ok && resp.BackendOk {            // line 193 — second term always true
```

`resp.Ok` already implies `resp.BackendOk`. Harmless, but it invites a reader
to believe the two are independent.

---

### 9. Status HTTP check does not drain the response body — Low

**Location:** `status.go:231-235`

```go
resp, err := s.client.Do(req)
if err != nil {
    return err
}
defer resp.Body.Close()
```

Closing without reading to EOF prevents connection reuse, so every `/_status`
request with `--target-status` configured opens a fresh backend connection.
Not a leak — `Close()` does release the connection — but it defeats keep-alive
on an endpoint designed for frequent polling.

Also worth noting: `s.client` has no `Timeout` and the check inherits only the
inbound request's context, so a hung backend ties up the status handler for as
long as the caller waits.

---

## Sweeps that came back clean

Reporting these explicitly, because a sweep that finds nothing is evidence about
the codebase rather than absence of effort.

| Sweep | Result |
|-------|--------|
| **Error wrapping** | Clean. Every production `fmt.Errorf` carrying an error uses `%w`. The three `%v` hits are non-error values (an ASN.1 OID, a `C.int` return code). |
| **Direct error comparison** | One outlier (finding 6); everything else uses `errors.Is`/`As`. |
| **Goroutine lifecycle** | All 49 concurrency sites in production code have a clear stop condition. `Proxy.Shutdown` correctly uses `sync.Once` — the comment at `proxy/proxy.go:171-175` documents the exact WaitGroup underflow it prevents. `fuse`'s unbuffered `returnedC` is always read, so no leak. |
| **Race detection** | `go test -race ./...` passes across all packages. |
| **`Accept()` WaitGroup accounting** | Traced by hand across the normal, error, and shutdown paths — balances in all three. The `Add(1)`-before-`Accept()` ordering at `proxy/proxy.go:411-416` is deliberate and correct. |
| **Fail-open analysis in `auth`** | Correct. `VerifyPeerCertificateServer` fails closed on an empty ACL; OPA evaluation errors return an error (deny) rather than falling through; `PinningEnabled()` is a single source of truth consistently honored by both the transport and the verifier. |
| **Flag mutual exclusion** | `--allow-spki-pin` / `--verify-spki-pin` exclusions are complete and symmetric across server and client, including the non-obvious `--use-workload-api` conflict. The client's deliberate *non*-conflict with `--disable-authentication` is correct and documented at `main.go:570-572`. |
| **`--proxy-protocol-mode` enum** | Initially looked unvalidated (`serverProxyProtoMode`'s `default:` case silently returns `ProxyProtocolConn`), but kingpin's `.Enum("conn", "tls", "tls-full")` at `main.go:81` makes the branch unreachable from the CLI. Not a bug. |
| **Wildcard over-matching** | Probed empty segments, trailing separators, `**` placement, and newline injection. No over-permissive match found. |
| **Cross-compilation** | linux/cgo, linux/nocgo, darwin/nocgo all build and vet clean. Only windows/nocgo fails (finding 4). |

---

## Test quality

The test suite is a strength. **95.5% statement coverage**, and the functions
below 80% are almost entirely platform stubs that cannot execute on the test
platform:

| Function | Coverage | Note |
|----------|---------:|------|
| `certstore/certstore.go:22 Open` | 0.0% | darwin/windows only |
| `certstore/certstore_other.go:11 openStore` | 0.0% | stub |
| `unix.go:58 runAsService` | 0.0% | not applicable on Linux |
| `proxy/semaphore.go:34 Release` | 0.0% | `unlimitedSemaphore` no-op |
| `unix.go:40 initSystemLogger` | 60.0% | syslog-dependent |
| `main.go:1212 getTLSConfigSource` | 65.0% | branches need PKCS#11/keychain |
| `status_linux.go:58 notifyServiceReloading` | 66.7% | needs systemd notify socket |

Observations:

1. **Behavioral gap behind the coverage number.** Finding 1 sits in code that is
   fully covered by line coverage — both `fuse` and `copyData` are exercised —
   but no test half-closes a connection while `--max-conn-lifetime` is set. High
   statement coverage is not the same as covering the interesting *state*
   combinations. The half-close path deserves a matrix test against each timeout
   flag.

2. **`errcheck` is disabled in `_test.go`** (`.golangci.yml`). Combined with the
   suite's size (~15k lines of test code), this leaves no automated pressure
   against tests that silently swallow an error and assert nothing.

3. **Windows integration-test port allocation is TOCTOU-prone.**
   `tests/common.py:86` documents that without `SO_REUSEPORT` the reservation
   socket is closed immediately, leaving a window where two parallel test
   processes can be handed the same port. This is a plausible source of
   intermittent Windows CI failures.

4. **`certstore` has no test coverage on Linux/FreeBSD** — `certstore_test.go`
   is gated `cgo && (darwin || windows)`, so `go test` reports "no test files"
   on the primary CI platform.

---

## Tooling recommendations

The project lint config (`.golangci.yml`) reports **0 issues**, which is real —
but it runs the `standard` preset plus `forbidigo` only. Running an extended set
surfaced 57 issues. Triaged:

### Worth adopting

| Linter | Findings | Rationale |
|--------|---------:|-----------|
| `errorlint` | 1 | Catches finding 6 exactly. Zero false positives here. |
| `noctx` | 2 | Flags `net.Listen` over `(*net.ListenConfig).Listen` at `socket/net.go:113`; the context-aware form is preferable on a listener path. |
| `intrange` / `copyloopvar` | 5 | Pure modernization for Go 1.22+, all in test files. Mechanical and safe. |
| `gocritic` | 6 | `assignOp` and `ifElseChain` cleanups; `status.go:182` is a genuine readability improvement. |

### Adopt with per-case review, not wholesale

- **`gosec` (25 findings)** — mostly noise *by design*: the JCEKS package must
  use MD5/SHA-1/3DES to read the legacy Java keystore format it exists to
  support. But three `G123` findings deserve a real look:
  `certloader/spiffe_tls_config.go:132`, `:168`, and `main.go:1160` all set
  `VerifyPeerCertificate` while leaving session resumption enabled and
  `VerifyConnection` unset. Go does not re-run `VerifyPeerCertificate` on a
  resumed session, so a client holding a valid session ticket can skip the ACL
  callback on resumption. Note the ACME path already handles exactly this
  hazard deliberately (`certloader/acmetlsconfig.go:302`,
  `SessionTicketsDisabled = true`, with a comment explaining the mTLS-bypass
  risk) — so the pattern is understood in one place but not applied in the
  others. **This is the highest-value follow-up item in this report and warrants
  its own focused security review**; I did not verify exploitability here.
- **`nilnil` (3 findings)** — `main.go:860` and `certloader/acmetlsconfig.go:299`
  return `(nil, nil)` as a deliberate, documented "feature disabled" signal.
  Correct as written; adopting the linter would require nolint annotations.
- **`perfsprint` (4 findings)** — micro-optimizations on non-hot paths. Low value.

### Coverage blind spots in the current config

Two exclusions in `.golangci.yml` are worth revisiting:

1. **The `std-error-handling` preset suppresses `Close()` errors.** Removing it
   surfaces 11 unchecked `Close()` calls. Most are genuinely fine (error paths,
   listener teardown), but for a TLS proxy an error from `Close()` on a *write*
   path can mean silent data truncation. The sites worth an explicit decision:
   `proxy/proxy.go:464` (`conn.Close` in the handler defer), `proxy/proxy.go:507`
   and `:513` (`backend.Close` on the PROXY-header error path).
2. **CI never compiles `GOOS=windows CGO_ENABLED=0`**, which is why finding 4
   went unnoticed. One `go vet` step across the tag matrix would have caught it.

---

## Reproducing this analysis

```bash
export PATH="/usr/local/go1.25.1/bin:$PATH"

# Baseline
go vet ./... && go tool golangci-lint run ./...
go test -race -count=1 ./...
go tool mage test:all && go tool cover -func=coverage/all.profile

# Build-tag matrix (windows/nocgo currently fails — finding 4)
for c in "GOOS=linux CGO_ENABLED=1" "GOOS=linux CGO_ENABLED=0" \
         "GOOS=darwin CGO_ENABLED=0" "GOOS=windows CGO_ENABLED=0"; do
  echo "### $c"; env $c go build ./... && env $c go vet ./...
done

# Extended linters (config not committed; see Tooling recommendations)
go tool golangci-lint run -c extended.yml ./...
```
