# Code Quality Analysis — `next` branch

| | |
|---|---|
| **Repository** | ghostunnel/ghostunnel |
| **Branch analyzed** | `next` @ `e960e41` ("Migrate timer metrics from Summary to Histogram", 2026-07-05) |
| **Diff vs `master`** | 31 files changed, +2,636 / −286 (excluding vendor) |
| **Analysis date** | 2026-07-09 |
| **Confirmed findings** | 22 (P1: 3, P2: 12, P3: 7) |

## Methodology

The codebase on the `next` branch was partitioned into six areas of concern, weighted toward the branch's
headline change (a new Prometheus-based `metrics` package replacing go-metrics, with rewired `main.go` and `proxy/`).
Each area went through a three-stage agent pipeline:

1. **Spec** — an agent derived a behavioral specification for the area from documentation (`README.md`,
   `docs/`), command-line flag help text, test names/intent, and reasonable expectations for production
   network-security software (fail-closed auth, no goroutine/fd leaks, hot reload never breaks live traffic, etc.).
   It was instructed *not* to derive the spec from the implementation.
2. **Check** — a second agent audited the implementation against that spec, with extra scrutiny on code that
   changed relative to `master`, citing concrete `file:line` evidence for every finding.
3. **Verify** — an adversarial verifier agent per finding, defaulting to "the finding is wrong", traced each
   claim through the real code (in two cases empirically reproducing it) and assigned a priority.

Findings were then deduplicated across areas. Raw findings: 24; after dedup: 23; confirmed by verification: 22; refuted: 1.
All 22 surviving findings carry a **confirmed** verdict (the verifier traced the failure path in real code).

**Priority scale:** P0 = user-visible breakage or security hole in a supported configuration (none found) · 
P1 = real bug or leak hit under realistic conditions · P2 = edge-case bug, doc mismatch, or notable gap · P3 = minor/maintainability.

## Areas of concern

| Area | Scope | Confirmed findings |
|---|---|---|
| **metrics** | `metrics/` — Prometheus registry, histogram timers, runtime collectors, Graphite bridge, legacy JSON export (**new on `next`**) | 2 |
| **proxy** | `proxy/` — connection forwarding, semaphore limits, PROXY protocol v2, metrics integration (**changed on `next`**) | 6 |
| **main** | `main.go`, `status*.go`, `signals.go`, `tls.go`, `unix.go`, landlock, windows service (**changed on `next`**) | 5 |
| **certloader** | `certloader/` — PEM/PKCS#12/JCEKS/PKCS#11/SPIFFE/ACME/keychain sources, hot reload, dialer/listener | 6 |
| **authpolicy** | `auth/`, `policy/`, `wildcard/` — access control, OPA, URI pattern matching | 0 |
| **socketcertstore** | `socket/`, `certstore/` — TCP/UNIX/systemd/launchd binding, macOS/Windows keychains | 3 |

The **auth/policy/wildcard** area — the security-critical access-control path — produced zero findings: the
checker found the certificate-field matching, wildcard handling, and OPA integration consistent with the spec.

## Findings

### P1 — should fix soon

#### 1. Backend dial failure and PROXY header write failure increment neither accept.error nor accept.success

`proxy/proxy.go:411` · area: **proxy** · category: `correctness` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Documented behavior 10: "Backend dial failure must close the client connection and count an error"; Reasonable expectation 3: for every accepted connection exactly one of accept.success or accept.error (or timeout counting) follows accept.total.

On backend dial failure the handler does only `p.logConditional(LogConnectionErrors, "error on dial: %s", err); return` (proxy/proxy.go:409-413), and on PROXY header write failure only `p.logConditional(...); backend.Close(); return` (proxy/proxy.go:422-427). Neither path touches `p.metrics.ErrorCounter`, while the handshake-failure path does (`p.metrics.ErrorCounter.Inc(1)`, line 394) and the success path increments SuccessCounter (line 430). Result: for every connection that fails at dial or at the PROXY header write, accept.total increments but neither accept.success nor accept.error follows, so accept.total permanently diverges from accept.success+accept.error and operators watching accept.error see no signal when the backend is down — arguably the single most important error condition for a proxy. (TestBackendDialError and TestProxyProtocolWriteFailureClosesBackend verify the connections are closed but never assert the counters, so this gap is untested.) The spec explicitly requires dial failures to be counted.

**Verifier assessment:** Traced proxy/proxy.go: dial failure (lines 409-413) and PROXY header write failure (lines 421-427) log and return without touching any counter, while accept.total already incremented (line 380); the only ErrorCounter increments in the package are the accept-loop (348) and handshake (394) paths. docs/networking/metrics.md:113 defines accept.error as "Failed connection attempts", so backend dial failures silently missing from it is a doc/behavior mismatch with real operational impact: during a backend outage accept.error stays flat and accept.total permanently diverges from success+error. Tests TestBackendDialError and TestProxyProtocolWriteFailureClosesBackend assert closure only, never counters, so nothing encodes this as intended; impact is observability-only (connections are correctly closed), hence medium/P1 rather than higher.

#### 2. SIGHUP/SIGUSR1 arriving during graceful drain kills the process because signal.Stop restores default disposition

`signals.go:42` · area: **main** · category: `correctness` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Documented behavior 12: SIGHUP/SIGUSR1 reload certificates and "never shutdown"; edge case 5: SIGHUP arriving mid-shutdown must not break shutdown; reasonable expectation 10: stable exit codes (0 clean drain / 1 timeout).

signalHandler registers reload+shutdown signals and unconditionally unregisters them when it returns: `signal.Notify(signals, append(shutdownSignals, refreshSignals...)...)` followed by `defer signal.Stop(signals)` (signals.go:41-42). After a shutdown trigger, shutdownFunc() runs and the function returns, executing the deferred signal.Stop while the process is still draining in-flight connections (serverListen/clientListen then sit in `p.Wait()`, main.go:868/910, for up to --shutdown-timeout, default 5m). Once signal.Stop removes the last handler, the Go runtime restores the default disposition for SIGHUP and SIGUSR1 — which is process termination. So a cert-rotation daemon or systemd `reload` sending SIGHUP during the drain window hard-kills ghostunnel: all in-flight connections drop and the process dies with a signal exit status instead of exiting 0 after a clean drain (or 1 on timeout). The test suite is itself aware of this hazard: unix_test.go:104-110 pre-registers a guard channel specifically "so ... the test process can't be killed by it". Keeping the signal handler registered (and draining/ignoring signals) until p.Wait() returns would fix this.

**Verifier assessment:** Traced the full path in code: signals.go:41-42 is the binary's only signal.Notify registration and its deferred signal.Stop fires when signalHandler returns after shutdownFunc, while the caller (main.go:867-868 / 909-910) then blocks in p.Wait() draining connections for up to --shutdown-timeout (default 5m, main.go:132). Once signal.Stop removes the last registration, the Go runtime restores the startup disposition of SIGHUP/SIGUSR1 (SIG_DFL = terminate), so a reload signal from systemd or a cert-rotation daemon during the drain window kills the process, dropping in-flight connections and exiting with a signal status instead of 0/1. No guard exists anywhere else; the guard in unix_test.go:104-110 protects only the test process and actually corroborates the hazard. Realistic but timing-dependent operational bug, not a security issue: P1/medium.

#### 3. Keychain reload leaks the opened certstore and all identity handles on every reload

`certloader/certstore_enabled.go:80` · area: **certloader** · category: `resource-leak` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 7 (resource lifecycle: sources must release underlying resources) and documented behavior 4 (SIGHUP/timed-reload is a routine, repeated operation that must not degrade the process).

certstoreCertificate.Reload() opens the OS certificate store and enumerates identities but never releases either:

    store, err := opener(c.logger)   // line 80
    ...
    identities, err := store.Identities(flags)   // line 90

Neither `store.Close()` nor `identity.Close()` is ever called anywhere in Reload(), on any path (success or error). The certstore API explicitly requires this: certstore/certstore.go defines `Close()` on both Store ("Close closes the store.") and Identity ("Close any manually managed memory held by the Identity."), and the package's own tests always `defer store.Close()` / `defer ident.Close()` (certstore/main_test.go:52,70). On darwin each identity retains CoreFoundation refs (certstore_darwin.go:76 "identRefs aren't owned by us initially. newMacIdentity retains them", released only in macIdentity.Close at line 247); on Windows winStore.Close (line 254) frees the CertOpenStore handle and winIdentity.Close (line 353) frees duplicated cert contexts and NCrypt key handles. There are no finalizers. Reload() runs on every SIGHUP/SIGUSR1 and every `--timed-reload` tick, so a long-running ghostunnel using `--keychain-identity` with timed reload leaks native memory/OS handles unboundedly: the store handle, every non-chosen candidate identity, and the previously chosen identity from the prior reload (only its crypto.Signer from the *current* reload is legitimately still in use).

**Verifier assessment:** Traced the full path: certloader/certstore_enabled.go Reload() never calls store.Close() or identity.Close() on any path; certstore_darwin.go CFRetains every SecIdentityRef (line 132) and caches copied SecCertificateRefs released only in macIdentity.Close (line 247), certstore_windows.go duplicates cert contexts (line 276) and holds CertOpenStore handles freed only in winStore.Close (line 254); no finalizers exist anywhere in the certstore package. Reload runs on every SIGHUP/SIGUSR1 and every --timed-reload tick (signals.go:99-120, main.go:709), so native memory and OS handles leak unboundedly in a long-running daemon using --keychain-identity. Refutation attempts failed: no guard, no caller-side close, and the package's own Windows Identities() error path closing identities (certstore_windows.go:193-196) plus macStore.Close's explanatory comment confirm the caller-must-close contract. Minor correction: on darwin the store itself does not leak (macStore.Close is a no-op); only identities leak there — the store-handle leak is Windows-only.

**Duplicates merged:** socketcertstore: Keychain reload leaks the certstore Store and all unchosen Identities on every reload

### P2 — worth fixing

#### 4. Shutdown() has a check-then-act race: concurrent calls can double-Done the WaitGroup and panic

`proxy/proxy.go:298` · area: **proxy** · category: `concurrency` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Documented behavior 4: "Multiple Shutdown() calls are safe (TestMultipleShutdownCalls) — idempotent, no panic"; Reasonable expectation 5: shutdown races must not panic or deadlock.

Shutdown is guarded only by a non-atomic check-then-act: `if err := p.context.Err(); err != nil { return }; p.cancel(); p.Listener.Close(); p.handlers.Done()` (proxy/proxy.go:298-306). Two goroutines calling Shutdown concurrently can both observe `p.context.Err() == nil` before either calls cancel(), and then both execute `p.handlers.Done()`. The second Done drops the WaitGroup counter negative and panics ("sync: negative WaitGroup counter"), crashing the process during shutdown. cancel() and Listener.Close() are idempotent, but Done() is not. TestMultipleShutdownCalls (proxy/proxy_test.go:315-326) only exercises sequential calls, so the test-pinned idempotency guarantee does not actually hold under concurrency (e.g. a library consumer wiring both a signal handler and an HTTP /_shutdown endpoint to Shutdown). Fix is a sync.Once or mutex around the cancel/Done pair.

**Verifier assessment:** Empirically reproduced: a temporary test spawning two goroutines calling Shutdown() concurrently panicked with "sync: negative WaitGroup counter" at proxy/proxy.go:305 within 0.034s. The guard at proxy/proxy.go:299 (p.context.Err() check) is non-atomic with the p.cancel()/p.handlers.Done() pair, and no mutex or sync.Once exists anywhere in the Proxy struct; TestMultipleShutdownCalls (proxy/proxy_test.go:315) only pins sequential idempotency. Mitigating scope: in the shipped ghostunnel binary Shutdown() is invoked solely from the single signalHandler goroutine (signals.go:39-96), whose select loop calls shutdownFunc once and returns, so the binary itself cannot race — only consumers importing the exported proxy package with multiple shutdown paths can. Hence a real, process-crashing latent bug in a public API contract, but an edge case in practice: P2, severity medium.

#### 5. closeRead/closeWrite hard-Close() *tls.Conn, so --close-timeout half-close draining never works on the TLS side of the pipe

`proxy/proxy.go:606` · area: **proxy** · category: `correctness` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Documented behavior 8: "When one side terminates, the other side is closed after --close-timeout (default 1s)" (flag help: "Timeout for closing connections when one side terminates"). Reasonable expectation 8: close-timeout logic applied when one direction finishes must not prematurely kill the other direction while it is still actively transferring within the timeout window.

closeRead/closeWrite only half-close `*net.TCPConn` and `*net.UnixConn`; every other type falls to `default: _ = c.Close()` (proxy/proxy.go:606-626). But in every real ghostunnel deployment one end of the fused pair is a `*tls.Conn`: server mode accepts via certloader.NewListener, whose Accept returns `tls.Server(c, ...)` (certloader/listener.go:48), and client mode dials a TLS backend. So when either direction's copy finishes, `copyData`'s defer (`closeRead(src); closeWrite(dst); setDeadline(src, p.CloseTimeout); setDeadline(dst, p.CloseTimeout)`, proxy/proxy.go:520-525) fully closes the TLS conn immediately, killing the opposite direction with zero grace. Concrete failure (server mode): a TLS client sends a request then half-closes (close_notify/FIN); copyData(backend, client) sees EOF and its defer calls `closeRead(client)` -> default -> `client.Close()`, so the backend's response can no longer be written back and is silently dropped — the CloseTimeout drain window and the setDeadline mechanism never come into play for the TLS side. This directly contradicts copyData's own comment: "By only closing the read/write sides specifically, we retain the ability to forward or return data in a case where a client has only half-closed the connection" (proxy/proxy.go:506-509). Note `tls.Conn` does support outbound half-close via CloseWrite (close_notify), which is unused; closeRead on a tls.Conn could be a no-op and let the CloseTimeout deadline tear it down, matching the documented semantics.

**Verifier assessment:** Traced the full path: certloader/listener.go:48 returns *tls.Conn, proxy.go:431 fuses it, and *tls.Conn falls to the default:c.Close() arm in closeRead/closeWrite (proxy.go:606-626), so copyData's defer (proxy.go:520-525) fully closes the TLS conn on first-direction EOF, killing the opposite direction's in-flight data with zero grace; the CloseTimeout deadline drain is dead code for the TLS side, contradicting copyData's own half-close comment (proxy.go:506-509) and the --close-timeout docs, and the resulting write error is silently swallowed by isClosedConnectionError. The only counter-evidence, TestCloseRead/WriteNonTCPConnection (proxy_test.go:700-710), is a mockConn characterization test of the fallback, not proof of intended TLS semantics — tls.Conn even has an unused CloseWrite (close_notify) method. Impact is silent data loss, but only for peers that half-close early while expecting return traffic (socat/nc-style piping), so P2 rather than P1.

#### 6. JKS keystores with private keys are rejected despite documentation claiming JKS support

`certloader/jceks/decoder.go:330` · area: **certloader** · category: `docs-mismatch` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Documented behavior 1/2 (JCEKS/JKS supported via --keystore with --storepass; `.jks` extension is an advertised auto-detected format) and formats.md "Ghostunnel can read Java keystores in JCEKS or JKS format".

The decoder accepts the JKS container magic (decoder.go:256 `if magic != jceksMagic && magic != jksMagic`, jceks.go:45 `jksMagic = 0xfeedfeed`) and decode.go maps `.jks` to this parser (decode.go:59), and docs/certificates/formats.md:115 states "Ghostunnel can read Java keystores in JCEKS or JKS format". But private-key recovery supports only the JCEKS protector:

    if !eKey.Algo.Algorithm.Equal(oidPBEWithMD5AndDES3CBC) {
        return nil, fmt.Errorf("%w: unsupported encrypted-private-key algorithm: %v", ...)
    }

where oidPBEWithMD5AndDES3CBC is 1.3.6.1.4.1.42.2.19.1 (pbemd5des3cbc.go:35). Real JKS files protect private keys with Sun's JKS key protector, OID 1.3.6.1.4.1.42.2.17.1.1 (SHA-1 based), which this code has no implementation for. Failure scenario: `keytool -genkeypair -storetype JKS -keystore server.jks` then `ghostunnel server --keystore server.jks --storepass ...` → startup fails with "unsupported encrypted-private-key algorithm: 1.3.6.1.4.1.42.2.17.1.1". Since a server keystore necessarily contains a private key, JKS support is effectively certificates-only, contradicting the docs and the `.jks` extension mapping. The existing TestParseJKSMagic only exercises a JCEKS-formatted stream with the JKS magic, so the gap is untested. Either implement the JKS key protector or correct the docs/error message to say JKS private keys are unsupported (convert with `keytool -importkeystore -deststoretype pkcs12`).

**Verifier assessment:** Reproduced end-to-end: generated a real JKS keystore with keytool (-storetype JKS) and called certloader.CertificateFromKeystore, which failed with "unsupported encrypted-private-key algorithm: 1.3.6.1.4.1.42.2.17.1.1" — decoder.go:330 only accepts the JCEKS protector OID 1.3.6.1.4.1.42.2.19.1 and no JKS KeyProtector (1.3.6.1.4.1.42.2.17.1.1) implementation exists anywhere in the repo. decode.go routes .jks/0xFEEDFEED to this parser and readJCEKSBlocks fails the whole load on any unrecoverable key, so any JKS server keystore (which must contain a private key) fails at startup, contradicting docs/certificates/formats.md:115 and flags.md:22 which advertise JKS support without caveat; TestParseJKSMagic only covers a cert-only entry. P2 not P1 because the failure is loud and immediate at startup with a clear error, cert-only JKS truststores still work, and conversion to PKCS#12 is a trivial documented workaround — the defect is an advertised-format/docs mismatch plus test gap rather than silent or security-relevant breakage.

#### 7. PKCS#11 reload publishes a certificate that may not match the reused HSM key, breaking all new handshakes instead of failing the reload

`certloader/pkcs11_enabled.go:83` · area: **certloader** · category: `error-handling` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Documented behavior 5 ("If reloading failed, the old state is kept" — a cert that no longer matches the key must not stop serving with the previously loaded material) and edge case 5 (cert replaced with one not matching the key between reloads: reload fails, old pair keeps serving).

pkcs11Certificate.Reload() reuses the cached key handle without verifying the newly read certificate still matches it:

    if old := c.cachedCertificate.Load(); old != nil {
        c.logger.Printf("pkcs11: re-using previously cached private key handle from module")
        certAndKey.PrivateKey = old.PrivateKey
    }

There is no comparison of `certs[0].PublicKey` against the cached leaf's public key (available as `old.Leaf.PublicKey`). If the cert file is replaced between reloads with a certificate for a *different* key (e.g. operator rotates the cert but forgets the HSM key, or writes the wrong file), Reload() succeeds and atomically publishes the mismatched cert+key pair. Every subsequent handshake then fails signature verification at the peer (server signs with the old HSM key, clients verify against the new leaf's public key), so the reload converts a working proxy into a fully broken one — the opposite of the package's contract that a bad reload keeps the old, working state serving. Failure scenario: `--pkcs11-*` server, cert file overwritten with a cert for another key, SIGHUP → reload logs success, all new TLS connections fail with `tls: invalid signature` until the file is fixed and another reload runs. A one-line public-key equality check (as tls.X509KeyPair does for the PEM path in keystore.go:84) would make the reload fail and keep the old pair, matching the PEM behavior tested by tests/test-server-reloads-split-cert-key.py. The docs (hsm-pkcs11.md:180-181) state the assumption but the code should enforce it fail-closed rather than fail-open into a broken serving state.

**Verifier assessment:** Traced the full path: pkcs11Certificate.Reload() (certloader/pkcs11_enabled.go:83-85) reuses the cached HSM private key with no public-key comparison against the newly read leaf, then unconditionally publishes the pair at line 100; no guard exists elsewhere (crypto/tls does not cross-check Leaf vs PrivateKey at handshake). The initial-load branch does validate via pkcs11key.New(..., Leaf.PublicKey), and the PEM path fails closed via tls.X509KeyPair (keystore.go:84), so the reload path's fail-open behavior is an unintended asymmetry that violates the Certificate interface contract (certloader/certificate.go:53-58, "If reloading failed, the old state is kept"). Requires operator error (cert rotated without HSM key) to trigger, but then a "successful" reload breaks all new handshakes — an availability bug in a supported configuration, untested by tests/test-server-pkcs11-module.py which only reloads the same cert.

#### 8. SPIFFE GetClientConfig/GetServerConfig block forever (no timeout) when the Workload API is unreachable or has no SVID

`certloader/spiffe_tls_config.go:74` · area: **certloader** · category: `error-handling` · severity: **medium** · verdict: **confirmed**

**Spec expectation:** Edge case 9: "SPIFFE: Workload API unreachable at startup (creation error, not hang)"; reasonable expectation 6 (fail-closed on load errors with actionable messages, preventing startup).

spiffeTLSConfigSource.newConfig creates the X509Source with an unbounded context:

    source, err := spiffeApi.NewX509Source(context.Background(), spiffeApi.WithClient(s.client))

Per the vendored go-spiffe (workloadapi/x509source.go:28-30) NewX509Source "blocks until the initial update has been received from the Workload API", and the client's watch loop retries Unavailable errors forever with backoff (workloadapi/client.go handleWatchError: only codes.Canceled and codes.InvalidArgument abort; everything else sleeps and retries). TLSConfigSourceFromWorkloadAPI itself succeeds even when the socket is dead because spiffeApi.New only constructs the client without dialing. Failure scenario: start `ghostunnel server --use-workload-api-addr unix:///run/spire/sockets/agent.sock` while the SPIRE agent is down (or the workload has no registration entry) → main.go:832 getServerConfig() hangs indefinitely inside NewX509Source; ghostunnel never binds its listener, never exits with an error, and gives the operator nothing but periodic go-spiffe retry logs. The spec expects Workload-API-unreachable-at-startup to surface as a creation error, not a hang; a context with a startup timeout (e.g. derived from --connect-timeout) or at minimum a documented bounded wait is needed.

**Verifier assessment:** Traced end-to-end: newConfig passes context.Background() to NewX509Source (certloader/spiffe_tls_config.go:74); vendored newWatcher (workloadapi/watcher.go:128-154) blocks until the first X.509 update, WatchX509Context's handleWatchError retries all errors except Canceled/InvalidArgument forever, and spiffeApi.New is lazy (confirmed by TestWorkloadAPISourceCreation using unreachable tcp://127.0.0.1:1), so with a dead agent socket or missing registration entry main.go:832/1089 hang indefinitely with no timeout guard anywhere. Mitigating details keep it P2 (original anchor was correct): the server listener is actually bound before the hang (main.go:826, contra the finding's "never binds"), go-spiffe emits periodic retry logs via the configured spiffeLogger, and the process self-heals once the agent becomes reachable — but there is no bounded wait, no startup error, and no doc stating this is by design.</parameter>
</invoke>


#### 9. graphiteTimeout comment claims it bounds a single flush (dial + write) but it is applied per-phase, so a flush is bounded by 2x the constant

`metrics/graphite.go:97` · area: **metrics** · category: `docs-mismatch` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Documented behavior 16: "Graphite flush is time-bounded: a single flush (dial + write) has a deadline" (graphite.go graphiteTimeout comment is cited as the source of truth).

The constant is documented as: "graphiteTimeout bounds a single flush (dial + write)." In graphiteFlush it is used twice with independent budgets: `conn, err := net.DialTimeout("tcp", addr.String(), graphiteTimeout)` (line 100) gives the dial its own 10s, and then `r.writeGraphiteConn(conn, graphiteTimeout, ...)` (line 105) sets a fresh 10s deadline via `conn.SetDeadline(time.Now().Add(timeout))` (line 112). A slow-but-not-dead endpoint (dial completes at ~9.9s, then the write stalls) keeps the push goroutine busy for up to ~20 seconds per flush, not the documented 10. Behavior is still time-bounded (the spec's intent of not wedging on OS-level TCP timeouts is met, and TestGraphiteWriteConnHonorsDeadline pins the write half), but the comment misstates the contract by 2x, which matters to anyone tuning --metrics-interval below ~20s: consecutive ticks can be dropped by the ticker while a single flush is still in flight. Either compute one shared deadline for dial+write (e.g. deadline := time.Now().Add(graphiteTimeout) used for both phases) or correct the comment to say each phase is bounded separately.

**Verifier assessment:** Traced the code directly: metrics/graphite.go:100 gives the dial its own 10s budget via net.DialTimeout(graphiteTimeout), and line 105 then calls writeGraphiteConn which sets a fresh 10s deadline at line 112 (time.Now().Add(timeout)) after the dial has completed, so a single flush can take up to ~20s while the comment at lines 94-97 claims graphiteTimeout "bounds a single flush (dial + write)". No guard, caller invariant, test, or doc establishes per-phase budgets as intended: TestGraphiteWriteConnHonorsDeadline pins only the write half, and docs/networking/metrics.md is silent on flush timeouts, leaving the incorrect comment as the sole spec text. The ticker-drop impact is also real (for range ticker.C at line 86; Go tickers drop ticks when the receiver is slow), but behavior remains time-bounded, so this is a docs-mismatch with minor operational tuning impact, not a functional bug.

#### 10. postOnce cannot treat 3xx responses as failure: redirect-following client silently drops the metrics payload and reports success

`metrics/jsonexport.go:120` · area: **metrics** · category: `error-handling` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Edge cases: "Non-2xx POST responses (including 3xx): treated as failure; response body must be drained/closed"; Documented behavior 14: non-2xx responses count as failed reports (logged).

postOnce checks `if resp.StatusCode < 200 || resp.StatusCode > 299 { return fmt.Errorf("metrics receiver returned %s", resp.Status) }`, but the *http.Client injected by main.go's newMetricsPostClient (main.go:588-599) has no CheckRedirect policy, so Go's default redirect handling applies. If the --metrics-url receiver answers 301/302/303 with a Location header (e.g. an auth-gated endpoint redirecting to a login page), the client reissues the request as a GET without the JSON body; if the redirect target returns 200, postOnce sees only the final 2xx response and returns nil. Concrete failure: receiver returns `302 Found -> Location: /login` and `/login` returns 200; every push cycle the metrics payload is silently discarded, nothing is logged through the injected Logger, and the operator believes metrics are being reported. Only an unfollowable 3xx (no Location) surfaces as an error. The unit tests only cover 500 (TestPostOnceNon2xx in metrics/sinks_test.go:117), so the 3xx path is also a test gap. Fix options: set CheckRedirect to return http.ErrUseLastResponse in newMetricsPostClient, or issue the request via http.NewRequest with a client that does not follow redirects, then the existing <200/>299 check would correctly reject 3xx.

**Verifier assessment:** Traced the full path: newMetricsPostClient (main.go:587-597) sets no CheckRedirect, so Go's default redirect policy applies; a 301/302/303 from the --metrics-url receiver is re-issued as a bodyless GET, and postOnce (metrics/jsonexport.go:120) only sees the final response — a 200 from the redirect target yields nil, silently dropping the payload with no log line, contradicting the function's own doc comment that a non-2xx rejection must be a failed report. No CheckRedirect exists anywhere in non-vendor code, no doc declares redirect-following intentional, and tests cover only 500/202 (sinks_test.go:117,131), confirming the test gap. Mitigations: the legacy go-sq-metrics client had the same behavior (parity, not regression), the quoted spec text is not in the repo, and impact is confined to metrics reporting under a misconfigured/auth-gated receiver — hence low severity, P2 (edge-case silent-failure bug plus test gap).

#### 11. PROXY protocol TLV build/encode failure fails open: header sent without TLS identity TLVs, logged unconditionally

`proxy/proxy.go:145` · area: **proxy** · category: `error-handling` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 1 (fail closed: errors before the fuse must not forward data with degraded/incorrect state) and documented behavior 6 (tls/tls-full modes carry PP2_TYPE_SSL and client-cert TLVs); documented behavior 15 (connection error logging is conditional on flags).

In proxyProtoHeader, `tlvs, err := buildTLVs(tlsState, mode); if err != nil { logger.Printf("proxy: failed to build PROXY protocol TLVs: %s", err) } else if ... if err := h.SetTLVs(tlvs); err != nil { logger.Printf(...) }` (proxy/proxy.go:145-154) — on either failure the connection proceeds and the header is written with connection info but none of the promised TLS metadata (no PP2_TYPE_SSL, no PP2_SUBTYPE_SSL_CLIENT_CERT in tls-full mode). buildTLVs fails when a sub-TLV value exceeds the 65535-byte TLV limit (e.g. an unusually large client certificate DER in tls-full mode), which is influenced by the peer. A backend in tls-full deployments that consumes the cert TLV for identity/authorization then silently receives a header claiming a plain connection instead of the connection being rejected — a fail-open on exactly the metadata the mode exists to convey. Additionally, these two log calls use `logger.Printf` directly instead of `p.logConditional`, bypassing the loggerFlags quiet settings that every other per-connection error respects.

**Verifier assessment:** Traced both error branches at proxy/proxy.go:145-154: on buildTLVs or SetTLVs failure the code logs and falls through, the header is written with connection info but zero TLS TLVs, and the connection is fused — while an adjacent failure mode (WriteTo error at proxy.go:422) correctly fails closed, showing the fail-open is an oversight, and docs promise the SSL sub-TLVs are "always present" in tls/tls-full modes. The buildTLVs branch is effectively unreachable (Go caps the Certificate handshake message at 65536 bytes so no sub-TLV value can exceed 65535), but the SetTLVs branch is reachable with a CA-signed leaf cert of ~65518-65527 DER bytes, whose outer PP2_TYPE_SSL TLV (5-byte header + sub-TLVs) exceeds the 65535 value limit — the backend then sees a header indistinguishable from conn mode. Impact is tempered because the client already passed ghostunnel's own verification/ACL and triggering needs a pathological CA-issued cert, so P2/low; the secondary claim (logger.Printf at :148/:151 bypassing loggerFlags while every other per-connection error uses p.logConditional) is confirmed by direct code comparison.

#### 12. Race between accept-loop handlers.Add(1) and Shutdown's handlers.Done(): Wait() can return (or WaitGroup panic) while a just-accepted connection is unhandled

`proxy/proxy.go:369` · area: **proxy** · category: `concurrency` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Documented behavior 3: Wait() blocks until listener closed AND connections drained; Reasonable expectation 2: "Wait() returning implies zero live connection goroutines"; Reasonable expectation 5: Shutdown() concurrent with in-flight Accept() must not panic.

The drain guarantee relies on New's guard count (`p.handlers.Add(1)`, proxy/proxy.go:293) plus a per-connection `p.handlers.Add(1)` at proxy/proxy.go:369 that runs only after `p.Listener.Accept()` returns. If Shutdown() fires in the window between a successful Accept (line 341) and the Add at line 369, Shutdown's `p.handlers.Done()` (line 305) drops the counter to zero: a concurrent Wait() unblocks and main proceeds to exit while the freshly accepted connection has not yet been registered or handled — violating "Wait() blocks until ... connections drained". Worse, the subsequent `Add(1)` on a counter that reached zero while a Wait() is in flight is documented WaitGroup misuse and can panic ("WaitGroup misuse: Add called concurrently with Wait"). The window is narrow but real, and hit exactly at the moment operators care about (graceful shutdown under load). Reserving the slot before Accept (e.g. Add before the blocking Accept, Done on error) or gating Add on the shutdown state under a lock would close it.

**Verifier assessment:** Traced the unguarded window in proxy/proxy.go between Listener.Accept() returning (line 341) and handlers.Add(1) (line 369); Shutdown() (line 305) can run handlers.Done() in that window with no lock or shutdown-state check, so with zero other active connections the counter hits 0 and Wait() (called by main.go:868/910 after signalHandler triggers Shutdown) returns while the just-accepted connection is unhandled, violating the documented drain contract at line 308. The WaitGroup-panic half of the finding is overstated for the shipped usage: main calls Wait() strictly after Shutdown() returns, so no waiter is registered at the zero transition and Add(1) on a clean WaitGroup is legal; a panic needs an additional active connection plus the accept goroutine staying descheduled for that connection's entire lifetime — theoretically possible, practically negligible. Real-world impact is one connection dropped at the exact instant of graceful shutdown, indistinguishable to clients from kernel accept-queue drops at listener close, so severity is low and priority P2 (edge-case bug, easily fixed by reserving the WaitGroup slot before the blocking Accept).

#### 13. Timed reload firing during shutdown flips /_status back to 200 and re-sends systemd READY=1 mid-stop

`signals.go:119` · area: **main** · category: `concurrency` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 4: /_status MUST accurately track lifecycle and report stopping after shutdown is triggered; edge case 5: shutdown wins over a concurrent reload; documented behavior 21: systemd stopping notification semantics.

The reload ticker goroutine (`go env.reloadHandler(*timedReload)`, main.go:709/763) is never stopped at shutdown; it keeps firing during the drain window. env.reload() ends with `env.status.Listening()` (signals.go:119), and Listening() unconditionally sets `s.listening = true` and calls `notifyServiceReady()` (status.go:99-106) without checking `s.stopping`. Stopping() had set `listening=false, stopping=true` (status.go:117-125), and statusHandler.status computes `resp.Ok = s.listening && resp.BackendOk` (status.go:159). So with `--timed-reload` set, a tick during the (up to 5-minute) drain makes /_status return HTTP 200 again — with body message "stopping" but a 200 code — so load balancers keying on the 503 re-add the instance while it is refusing new connections (listener already closed). On Linux it additionally sends RELOADING=1 followed by READY=1 to systemd after STOPPING=1 was already sent. Listening() (and reload()) should not resurrect the healthy state once stopping is set, or the reload goroutine should be stopped when shutdown begins.

**Verifier assessment:** Traced the full path: the timed-reload goroutine (main.go:709/763, signals.go:99-106) uses time.Tick with no cancellation and keeps firing during the drain; reload() unconditionally calls status.Listening() (signals.go:119), which sets listening=true and sends systemd READY=1 with no stopping guard (status.go:99-106), so a mid-drain tick does flip internal state back to healthy and emits RELOADING=1/READY=1 after STOPPING=1. However, the claimed LB impact is overstated: shutdownFunc (signals.go:44-55) shuts down the status HTTP server immediately after Stopping(), closing the listener, so /_status is unreachable (connection refused) for essentially the whole drain window and the resurrected 200 is only observable in a milliseconds-wide race; systemd also ignores READY=1 in deactivating states. Real state-machine/notify-ordering bug in a supported config, but with minimal observable impact — severity low, P2.

#### 14. Data race on macIdentity.crt/.chain: unsynchronized cache writes during concurrent TLS handshake signing

`certstore/certstore_darwin.go:148` · area: **socketcertstore** · category: `concurrency` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectations #4 (Concurrency): concurrent use of certstore identities must be race-free; the rest of the struct (kref/cref) already implements atomic double-checked locking, showing the intended contract.

macIdentity is handed to crypto/tls as the private key: certloader stores the identity itself as the signer (`PrivateKey: signer` in certloader/certstore_enabled.go:166, where `Signer()` returns `i` at certstore_darwin.go:217). Every TLS handshake therefore calls `Sign()` -> `getAlgo()` -> `Certificate()`, and `Certificate()` unconditionally writes the shared field without holding the mutex: `i.crt = crt` (line 148). `CertificateChain()` similarly does an unsynchronized read `if i.chain != nil { return i.chain, nil }` (line 155) and write `i.chain = chain` (line 204). The struct clearly intends concurrent use — `kref`/`cref` use atomic.Uintptr plus double-checked locking under `i.mu` (getKeyRef/getCertRef, lines 398-441) — but `crt` and `chain` were left unprotected. Two simultaneous handshakes on a keychain-backed server produce concurrent writes to `i.crt`, a data race under the Go memory model (flagged by -race, undefined visibility guarantees). Secondary defect on the same line: `Certificate()` never reads its own cache, so every signature re-runs SecCertificateCopyData + x509.ParseCertificate, making the cache field write-only overhead that exists solely to create the race.

**Verifier assessment:** Traced the full path in real code: certloader/certstore_enabled.go:166 stores the macIdentity itself as tls.Certificate.PrivateKey (Signer() returns i at certstore_darwin.go:217), and crypto/tls invokes both Public() (line 267) and Sign()->getAlgo() (line 335) per handshake, each reaching the unsynchronized shared write `i.crt = crt` at line 148 with no lock held (getCertRef releases i.mu before returning); kref/cref use atomic double-checked locking, proving concurrent use is the intended contract. So concurrent handshakes on a keychain-backed listener produce a genuine Go-memory-model data race flagged by -race, plus the cache is write-only so every handshake redundantly re-parses the certificate. However, the race writes equivalent non-nil pointers (untearable on darwin amd64/arm64) and no reader can observe nil, and the chain field (lines 155/204) is only exercised sequentially from Reload() on freshly constructed identities — so no crash, corruption, or wrong-behavior scenario exists, capping severity at low/P2.

#### 15. checkStatus sign-extends negative SECURITY_STATUS, so the NTE_BAD_ALGID -> ErrUnsupportedHash mapping never fires and error codes print garbled

`certstore/certstore_windows.go:732` · area: **socketcertstore** · category: `error-handling` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectations #3 (`Signer()` MUST return ErrUnsupportedHash for unsupported hash algorithms) and #9 (errors are diagnosable); expectation #8 (signing mismatches must surface as errors, i.e. clear ones).

`type securityStatus uint64` (line 730) and `func checkStatus(s C.SECURITY_STATUS) error { ss := securityStatus(s); ... if ss == NTE_BAD_ALGID { return ErrUnsupportedHash }` (lines 732-741). SECURITY_STATUS is `typedef LONG SECURITY_STATUS` (signed 32-bit), which cgo maps to int32. All NCrypt failure codes are negative HRESULTs (NTE_BAD_ALGID = 0x80090008 is -2146893816 as int32), and converting a negative int32 to uint64 sign-extends: securityStatus becomes 0xFFFFFFFF80090008, which never equals the untyped constant `NTE_BAD_ALGID = 0x80090008` (line 59). Two consequences: (1) an NCryptSignHash failure with a bad algorithm returns a generic securityStatus error instead of the sentinel ErrUnsupportedHash that callers (and crypto/tls signature-scheme negotiation) can react to; (2) `func (ss securityStatus) Error() string { return fmt.Sprintf("SECURITY_STATUS 0x%08X", uint64(ss)) }` (lines 746-748) prints every real failure as e.g. "SECURITY_STATUS 0xFFFFFFFF80090008" instead of the recognizable HRESULT 0x80090008, hurting diagnosability of CNG signing failures. The fix is to compare/format the value masked to 32 bits (or make securityStatus uint32). Contrast with errCode, which is safe because GetLastError() returns an unsigned DWORD.

**Verifier assessment:** Traced the type flow: C.SECURITY_STATUS is typedef LONG (int32 via cgo on Windows), and converting a negative int32 to the uint64-based securityStatus type sign-extends per the Go spec, so securityStatus(NTE_BAD_ALGID failure) = 0xFFFFFFFF80090008 never equals the constant 0x80090008 — line 739's ErrUnsupportedHash mapping is dead code, and Error() at line 747 prints the sign-extended value for every real NCrypt failure. No guard mitigates it: the RSA path pre-validates hashes in Go (line 460) and the CAPI path uses the unsigned DWORD-based errCode correctly (line 549), but sign-time KSP rejections and NCryptDeleteKey failures (lines 482/489/607) hit the broken branch. Failures still surface as errors (ERROR_SUCCESS==0 matches fine), so impact is limited to the lost sentinel contract and garbled HRESULT diagnostics on Windows keychain error paths — a real but low-severity error-handling bug.

### P3 — minor

#### 16. isClosedConnectionError does not recognize ECONNRESET/EPIPE, so routine peer resets are logged as copy errors

`proxy/proxy.go:597` · area: **proxy** · category: `error-handling` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 6: "expected closed-connection errors (use of closed network connection, EOF, ECONNRESET, EPIPE) must be distinguished from real errors so half-closed teardown is not logged as failure".

isClosedConnectionError only matches `strings.Contains(err.Error(), "closed network connection")` (with an op filter) or `strings.Contains(err.Error(), "closed pipe")` (proxy/proxy.go:597-604). Abrupt peer termination surfaces as net.OpError wrapping syscall.ECONNRESET ("connection reset by peer") or syscall.EPIPE ("broken pipe"), which matches neither string, so copyData logs it via `p.logConditional(LogConnectionErrors, "error during copy: %s", err)` (proxy/proxy.go:562). Any client or backend that resets instead of FIN-closing — extremely common with impatient clients and load-balancer health checks — produces a spurious error log line per connection when --quiet=conn-errs is not set, drowning real errors. The expected-error classes the spec names (ECONNRESET, EPIPE) are exactly the ones missing; TestIsClosedConnectionError covers neither.

**Verifier assessment:** Traced in real code: isClosedConnectionError (proxy/proxy.go:597-604) only matches "closed network connection" inside a read/write net.OpError or "closed pipe", and once errors.As matches net.OpError the "closed pipe" fallback is skipped; peer aborts arrive as net.OpError wrapping syscall.ECONNRESET ("connection reset by peer") or EPIPE ("broken pipe"), so copyData logs them at proxy/proxy.go:562 under LogConnectionErrors, which is on by default (main.go:1112 clears it only with --quiet=conn-errs). No guard exists elsewhere and neither TestIsClosedConnectionError nor TestCopyDataErrorClassification covers these errnos. However, the suppression comment's stated intent (hide errors from the proxy's own teardown) is actually met, a peer RST is a genuine abnormal remote event whose logging is a defensible choice with an existing off switch, and impact is log noise only — so this is a confirmed but minor logging/test-coverage gap, not a functional bug.

#### 17. Metrics push/collector goroutines and CA-bundle load run before per-mode flag validation

`main.go:663` · area: **main** · category: `error-handling` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 1: every flag-validation failure MUST occur before any listener is bound or background goroutine started; reasonable expectation 2: errors after goroutines start must stop them on the way out.

run() calls `proxyMetrics, metricsRegistry, err := setupMetrics()` (main.go:663) before dispatching to `serverValidateFlags()` (main.go:671) or `clientValidateFlags()` (main.go:719). setupMetrics immediately starts background goroutines — `registry.StartRuntimeCollector(*metricsInterval)`, `registry.StartGraphitePush(...)`, `registry.StartPostLoop(...)` (main.go:561-578) — and performs I/O (`certloader.LoadTrustStore(*caBundlePath)`, main.go:572). So e.g. `ghostunnel server --metrics-graphite host:2003 --allow-all --allow-cn foo ...` spins up the graphite push loop (and with a short --metrics-interval may even emit a push) before the "--allow-all is mutually exclusive" validation error aborts startup; nothing on the error path stops those goroutines — they die only because main() exits. The same ordering also runs Landlock setup (main.go:657) before mode-specific validation. Master had the same ordering, but the new setupMetrics extraction was an opportunity to move the validation-before-side-effects boundary. Moving the serverValidateFlags/clientValidateFlags calls (or setupMetrics) so all flag validation completes before any goroutine starts would satisfy the spec invariant.

**Verifier assessment:** Traced the ordering in main.go: setupMetrics() at line 663 starts ticker-driven goroutines (StartRuntimeCollector/StartGraphitePush/StartPostLoop) and loads the CA bundle before serverValidateFlags (line 671) / clientValidateFlags (line 719) run, so per-mode validation failures do occur after goroutines start. However, impact is minimal: all three loops fire only after a full --metrics-interval (default far exceeds the microseconds before the validation error exits the process), no listener is bound, and the no-stop-mechanism lifecycle is explicitly documented as by design in metrics/runtime.go:119-121, graphite.go:79-81, and jsonexport.go:91-93 (goroutines live until process exit, which the error path reaches immediately). The ordering is also unchanged from master, so this is a pre-existing startup-hygiene nit — real code behavior as described, but with no realistic user-visible harm beyond log-line ordering on a failed start.

#### 18. serveStatus leaks the bound status listener when building the TLS server config fails

`main.go:989` · area: **main** · category: `resource-leak` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 2: any error after resources are acquired MUST close listeners on the way out — no dangling listeners after run() returns an error.

In serveStatus, after `listener, err := socket.Open(network, address)` succeeds (main.go:980), the HTTPS branch has two error returns that never close it: `config, err := buildServerConfig(...); if err != nil { return err }` (main.go:987-990) and `serverConfig, err := getServerConfig(env.tlsConfigSource, config); if err != nil { return err }` (main.go:993-996). Contrast with the callers, which do close the proxy listener on a serveStatus error (`listener.Close()` at main.go:855/897), and with serverListen's own getServerConfig error path which closes its listener (main.go:834). buildServerConfig can fail here for an invalid --max-tls-version in client mode (where it is not otherwise exercised before this point on the server-status path), and getServerConfig can fail for source-specific reasons. Impact is limited because run() returns the error and the process exits, but per the spec's cleanup expectation the error paths should `listener.Close()` before returning (e.g. via a defer-on-error).

**Verifier assessment:** The missing listener.Close() on the two HTTPS-branch error returns in serveStatus (main.go:989, 995) is real and inconsistent with sibling error paths (main.go:834, 855, 897). However, the finding's primary trigger is wrong: buildServerConfig at main.go:987 cannot fail there in either mode, because cipher suites are validated at flag-parse time and an invalid --max-tls-version fails earlier via serverListen's buildServerConfig (main.go:797) in server mode and clientBackendDialer's buildClientConfig (main.go:1037, identical buildConfig validation) in client mode. Only the getServerConfig return (main.go:995) is reachable, via a transient SPIFFE workload-API failure (certloader/spiffe_tls_config.go:65-77 dials fresh each call) or a hot-reload race after the CanServe() check; when it fires, run() returns and main() immediately calls os.Exit, so the fd dangles only for microseconds — no user-observable impact in any supported configuration.

#### 19. --target-status HTTP healthcheck is not bounded by --connect-timeout; relies incidentally on the status server's hardcoded 30s ReadTimeout

`status.go:209` · area: **main** · category: `error-handling` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 5: the backend healthcheck MUST be bounded by a timeout (connect-timeout) so a hung backend cannot wedge status-handler goroutines under health-check polling.

newStatusHandler builds the healthcheck client with no timeout: `client := http.Client{Transport: &http.Transport{DialContext: statusDialer{dial}.DialContext}}` (status.go:78-82), and checkBackendStatus issues `resp, err := s.client.Do(req)` (status.go:209) with only the inbound request's context. Connection establishment is bounded (the injected dial func uses `net.Dialer{Timeout: *connectTimeout}`, main.go:1026), but the wait for HTTP response headers is not: a backend that accepts the TCP connection and never responds wedges the /_status handler goroutine. In practice the handler is eventually released only as a side effect of the status http.Server's hardcoded `ReadTimeout: 30 * time.Second` (main.go:1004) — the expired read deadline fails the background read and cancels r.Context() — which is roughly 3x the default --connect-timeout (10s), ignores the operator's configured value entirely, and is a fragile incidental mechanism rather than a deliberate bound. The default raw-TCP check path is correctly bounded; only the --target-status HTTP path is affected. Setting client.Timeout (or wrapping ctx with context.WithTimeout(*connectTimeout)) in checkBackendStatus would make the bound explicit.

**Verifier assessment:** Traced the full path: status.go:78-82 builds an http.Client with no Timeout and a custom Transport with no ResponseHeaderTimeout, and checkBackendStatus (status.go:209) bounds client.Do only by r.Context(). The dial func (main.go:1026) bounds TCP connect with --connect-timeout, but the wait for response headers is unbounded except for the status server's hardcoded ReadTimeout: 30s (main.go:1004), whose deadline expiry cancels the request context via the background read — exactly the incidental mechanism the finding describes. No guard, test, or comment suggests this is intentional; the raw-TCP fallback path is deliberately bounded, making the asymmetry an oversight. Impact is bounded (max ~30s stall per probe goroutine, no leak), so this is a minor robustness gap, not a realistic operational hazard.

#### 20. Certificate and trust store are published via two separate atomic stores, so readers can observe a mixed new-cert/old-pool state during reload

`certloader/keystore.go:99` · area: **certloader** · category: `concurrency` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectation 1: "A reload must atomically publish the new cert+truststore pair (e.g. one atomic pointer store); a concurrent reader must never observe ... a mixed old-cert/new-pool combination."

All three reloadable Certificate implementations publish the reloaded pair with two independent atomic stores:

    c.cachedCertificate.Store(&certAndKey)
    c.cachedCertPool.Store(bundle)

(keystore.go:99-100; identically pkcs11_enabled.go:100-101 and certstore_enabled.go:173-174, via the two separate `atomic.Pointer` fields in baseCertificate, certificate.go:28-29). A goroutine executing certTLSConfig.GetServerConfig / a handshake's GetCertificate callback between the two stores observes the *new* certificate paired with the *old* CA pool (and the cached-config layer will happily build and cache a config from that mixed read until the pool store lands and forces a rebuild). The spec explicitly calls for the pair to be published together ("e.g. one atomic pointer store") so a reader never sees a mixed old-cert/new-pool combination. Concrete failure scenario: coordinated CA+leaf rotation via SIGHUP; a client whose certificate chains only to the newly added CA connects in the window between the two stores and is rejected (`tls: bad certificate`) because ClientCAs still points at the old pool while the server already presents the new leaf. The window is microseconds and self-healing, hence low severity, but it is a direct deviation from the atomic-swap expectation; storing a single struct pointer holding {cert, pool} (mirroring the cachedTLSConfig pattern in certtlsconfig.go:22-25) would close it. Note the new TestCachedCertServerConfigConcurrentReload only validates pool↔config pairing, not cert↔pool pairing, so this is also untested.

**Verifier assessment:** Traced the exact interleaving: all three Reload implementations (keystore.go:99-100, pkcs11_enabled.go:100-101, certstore_enabled.go:173-174) publish cert then pool via two independent atomic.Pointer stores with no lock, and certtlsconfig.go serves the cert through a live GetCertificate callback against a config whose ClientCAs was baked from an earlier GetTrustStore() read, so a handshake between the two stores observably pairs the new leaf with the old CA pool; the cited test at cached_config_test.go:120 indeed only checks pool-config pairing. However, impact is lower than even the finding implies: the window is sub-microsecond and self-healing (pool pointer is the config-cache key), and the proposed single-pointer fix would not close the inherent, documented-by-design window where the live cert callback fires against a config built before the reload (certtlsconfig.go:10-21) — fully atomic cert+pool observation would require snapshotting the cert into the config, a design change. Real concurrency wart and test gap, negligible user impact.

#### 21. spiffeTLSConfig panics on a nil base *tls.Config while cert- and ACME-backed sources handle it

`certloader/spiffe_tls_config.go:108` · area: **certloader** · category: `api-design` · severity: **low** · verdict: **confirmed**

**Spec expectation:** tlsconfig.go interface doc: "The base configuration is cloned and used as a base for all returned TLS configuration" — implying any base accepted by one source (including nil, handled by certTLSConfig and acmeTLSConfig) is handled uniformly; reasonable expectation 5 (the single SPIFFE build must be correct).

The other two TLSConfigSource implementations normalize a nil base (certtlsconfig.go:79-81 `if base == nil { base = new(tls.Config) }`; acmetlsconfig.go:229-231 same), but spiffeTLSConfigSource.newConfig stores `base` unchecked and buildClientConfig/buildServerConfig do:

    config := c.base.Clone()
    ...
    config.InsecureSkipVerify = true

crypto/tls's (*Config).Clone returns nil for a nil receiver, so with a nil base `config` is nil and the very next field assignment panics with a nil-pointer dereference (same in buildServerConfig at line 138). Failure scenario: any caller doing `source.GetServerConfig(nil)` — legal per the TLSConfigSource interface, exercised against other sources in main_test.go:670 — gets a runtime panic on the first GetServerConfig()/GetClientConfig() call instead of a config derived from defaults. Production main.go currently always passes a non-nil config, so this is an API inconsistency/latent panic rather than a live bug, but because the SPIFFE config is build-once-cache-forever (spiffe_cached_config_test.go header: "a wrong config here would never self-correct") the inconsistency is worth fixing with the same two-line guard the sibling sources use.

**Verifier assessment:** Traced the full path: spiffeTLSConfigSource.newConfig (certloader/spiffe_tls_config.go:73-84) stores base unchecked, and buildClientConfig/buildServerConfig (lines 108, 138) call c.base.Clone() — which returns nil for a nil receiver per crypto/tls docs — then immediately assign fields, panicking on a nil base. The sibling sources guard nil (certtlsconfig.go:79-81, acmetlsconfig.go:229-231) and nil bases are exercised in their tests plus main_test.go:670/678, so nil is de facto legal for the interface. However, all production callers in main.go (lines 832, 993, 1089) pass a non-nil config built earlier, so the panic is latent — an API inconsistency fixable with the same two-line guard, not user-visible breakage.

#### 22. launchdSocket leaks the malloc'd fd array and the activated fds when launchd returns more than one socket

`socket/launchd_enabled.go:46` · area: **socketcertstore** · category: `resource-leak` · severity: **low** · verdict: **confirmed**

**Spec expectation:** Reasonable expectations #2 (No fd leaks): "error paths must not leak the C fd array or CString"; edge case "launchd returning 0 fds, >1 fds".

The count check runs before the free is registered: `length := int(c_cnt); if length != 1 { return nil, fmt.Errorf("expected exactly one socket ... found %d", address, length) }` (lines 45-48) and only afterwards `ptr := unsafe.Pointer(c_fds); defer C.free(ptr)` (lines 49-50). launch_activate_socket allocates the fds array and transfers ownership of both the array and the dup'd descriptors to the caller, so on the `length > 1` error path (e.g. a plist that configures IPv4+IPv6 sockets under one name, the exact scenario tests/test-client-launchd-socket-activation-error.py exercises) the C array is never freed and the N activated file descriptors are never closed. Impact is bounded because ghostunnel aborts startup on this error, but if the status listener or any future caller treats the error as non-fatal the fds stay open for the process lifetime, and it directly violates the spec's error-path cleanup requirement. Moving the `defer C.free(ptr)` (plus closing each fd) above the length check fixes it; the success path is fine (net.FileListener dups, then `defer file.Close()`).

**Verifier assessment:** Traced socket/launchd_enabled.go:45-50: the length != 1 early return at line 47 precedes the defer C.free(ptr) at line 50, and per the launch_activate_socket contract the caller owns the malloc'd array and dup'd fds once the call returns 0, so the cnt>1 path leaks both. However, every caller (main.go:826/875/980) treats the error as fatal and the process exits immediately, so the leak is never observable in any supported configuration; also, the cited integration test does not actually exercise the cnt>1 path (it tests launchd activation failing outside a launchd context). Real spec violation and trivially fixable, but purely a hygiene issue on an abort-startup path — P3, low severity.

## Refuted findings

One finding was raised by a checker but overturned by its adversarial verifier:

- **Wait() can return before per-connection ConnTimer.UpdateSince defers run, leaving live handler goroutines after drain** (`proxy/proxy.go:377`, area: proxy) — The mechanical claim is accurate — in proxy/proxy.go the defer at line 377 (ConnTimer.UpdateSince) and the tail of the cleanup defer (connSemaphore.Release at 386) run after p.handlers.Done() at 385, so Wait() can return microseconds before the goroutine fully exits — but this ordering is explicitly documented as intentional at lines 372-376 ("UpdateSince is deferred first so it fires last... matching Timer.Time's 'measure the whole handler'"), and the claimed consequences are not observable: Wait()'s documented contract (proxy.go:308) is "listener closed, connections drained," which holds since conn.Close() precedes Done(); after Wait() main.go simply returns and the process exits via exitFunc with no post-drain metric read, snapshot, or final push anywhere (StartGraphitePush/StartPostLoop in metrics/graphite.go and metrics/jsonexport.go are periodic loops with no shutdown flush, so the entire last interval is dropped at exit regardless of defer ordering). The timer is a prometheus client_golang histogram (metrics/timer.go) whose Observe is atomic, so a concurrent periodic push is not a data race, the released semaphore is per-proxy state about to be discarded, and no test (no goleak, no post-Wait metric assertion) relies on the stricter "zero goroutines after Wait" invariant the finding invents.

## Appendix: behavioral specifications

The per-area specs used as the audit baseline. Each was derived from docs, flag help, and test intent.

<details>
<summary><b>Metrics package (NEW on next branch)</b> (2 raw findings)</summary>

# Behavioral Specification: `metrics` package (next branch)

## Purpose

The `metrics` package is Ghostunnel's single metrics backend, replacing `rcrowley/go-metrics`, `go-sq-metrics`, and the cyberdelia/deathowl bridges with one `prometheus/client_golang` registry. It owns the hot-path instrument handles (counters, a gauge-like `conn.open`, histogram-based timers), plus three export sinks: native Prometheus exposition, a legacy dot-named JSON export (HTTP pull and periodic POST), and a Graphite line-protocol TCP push. Metric names and legacy wire formats are an exported compatibility surface and must be preserved exactly.

## Documented behavior

1. **Canonical metric names are fixed**: `conn.open`, `conn.timeout`, `accept.total`, `accept.success`, `accept.error`, `accept.timeout` (counters), `conn.handshake`, `conn.lifetime` (timers). Names must not change across the migration (docs/networking/metrics.md "Metric Names"; metrics.go package comment).
2. **`conn.open` is gauge-like**: incremented/decremented as connections open/close; internally a Prometheus gauge, but rendered as a counter (`.count`) in Graphite/JSON output to preserve historical format (docs table note; `registerOpenGauge` comment).
3. **Prefix**: `--metrics-prefix` (default `ghostunnel`) is prepended to all metric names in every output format (main.go flag; docs; `TestPrefixApplied`).
4. **JSON format** (`/_metrics/json`, bare `/_metrics`, and `--metrics-url` POST body): an array of `{timestamp, metric, value, hostname}` objects with dot-separated names. Counters/gauges emit a single value; timers expand to exactly `count`, `mean`, and `50/75/95/99-percentile`. `min`/`max` were removed in v1.11.1 (docs "JSON format" + migration note; `TestJSONFieldSet`).
5. **Integer-valued counters encode as plain integers** in JSON (no trailing `.0`) (`TestJSONIntegerEncoding`; jsonexport.go comment).
6. **Prometheus format** (`/_metrics/prometheus`): dots/dashes flattened to underscores (reproducing the old bridge's `flattenKey`); counters exposed as counters, `conn.open` as a gauge, timers as native Prometheus histograms with `_bucket{le=...}`/`_sum`/`_count` plus a native (exponential) histogram representation; standard `go_*`/`process_*` collectors also exported (docs "Prometheus ≥ v1.11.1"; `TestPrometheusNative`, `TestFlatten`).
7. **Graphite push** (`--metrics-graphite=ADDR`): line protocol `<path> <value> <timestamp>\n` over raw TCP every `--metrics-interval`. Counters emit `.count`, gauges `.value`, timers `count/mean/{50,75,95,99}-percentile`; dropped go-metrics fields (`min`, `max`, `count_ps`, `std-dev`, rates, `999-percentile`) must be absent (graphite.go comments; docs migration note; `TestGraphiteFieldSet`, `TestGraphitePush`, tests/test-*-metrics-graphite*.py).
8. **JSON POST push** (`--metrics-url=URL`): POST the JSON snapshot every `--metrics-interval` (default 30s). URL must start with `http://` or `https://` (validated at startup with an error message saying so) (main.go:258, flag help; docs "Metrics Export"; tests/test-*-metrics-bridge.py).
9. **Timer units are nanoseconds** in all sinks, matching go-metrics' historical units (timer.go comment; `TestTimerObservationsAreNanoseconds`; docs bucket description).
10. **Legacy percentiles are bucket-interpolated** from the classic histogram buckets, mirroring PromQL `histogram_quantile`; an estimate above the highest finite bucket boundary is capped at that boundary (docs migration note; `TestHistogramQuantile*`).
11. **Metrics gating**: when neither `--status`, `--metrics-graphite`, nor `--metrics-url` is set, `NilMetrics()` no-op handles are used and no registry, collector goroutine, or push loop is created. A push sink alone (e.g. Graphite without `--status`) must enable full collection (main.go `setupMetrics` comment; `TestNilMetricsAreNoOps`; tests/test-server-metrics-graphite-only.py).
12. **`--metrics-interval` must be positive** when metrics are enabled; a non-positive value is a startup error (main.go:549).
13. **Runtime collector**: `ghostunnel.runtime.*` gauges plus a GC-pause timer, refreshed every `--metrics-interval`, reproducing go-sq-metrics' `collectMetrics`; an initial synchronous collection populates gauges before the first scrape/push (runtime.go comments; `TestRuntimeCollector`, `TestStartRuntimeCollectorIdempotentAndTracksGC`).
14. **A failing `--metrics-url` receiver must not break the instance**: non-2xx responses count as failed reports (logged), the push loop keeps retrying, and the tunnel keeps proxying (tests/test-server-metrics-url-error.py; `TestPostOnceNon2xx`, `TestPostOnceSuccess`).
15. **Graphite failures are surfaced, not fatal**: dial errors and mid-report write errors are returned/logged and the push loop continues; a partial write is never reported as success (bufio latches the first error) (graphite.go comments; `TestGraphiteFlushDialError`, `TestGraphiteWriteError`).
16. **Graphite flush is time-bounded**: a single flush (dial + write) has a deadline so a dead/firewalled endpoint cannot block the push goroutine for OS-level TCP timeouts (graphite.go `graphiteTimeout`; `TestGraphiteWriteConnHonorsDeadline`).

## Reasonable expectations

1. **Hot-path cost**: `Counter.Inc/Dec` and `Timer.UpdateSince` must be lock-light (client_golang atomics); no allocation, snapshotting, or I/O on the connection path. `NilMetrics` handles must be true no-ops.
2. **Thread-safety**: concurrent timer observations must never lose counts (`TestTimerConcurrentObserve`); registering instruments concurrently with `snapshot()`/serialization must not race or panic (`TestConcurrentRegisterAndSnapshot`); descriptor list access must be mutex-guarded.
3. **Idempotent collector startup**: concurrent/repeated `StartRuntimeCollector` calls must register and start exactly once (racing `MustRegister` would panic); later calls' intervals are ignored (`TestStartRuntimeCollectorConcurrent`).
4. **Snapshot consistency**: one snapshot = one `Gather()`; all values in a single JSON/Graphite report come from the same gather. A gathered result missing a family (e.g. registered after gather) must degrade to zero values, not panic (`TestReadersHandleMissingFamily`, `TestTimerCountMissing`).
5. **No NaN/Inf on the wire**: empty timers produce NaN interpolated percentiles; these must be clamped to 0 so JSON marshaling never fails and Graphite never emits `NaN` (`TestJSONEmptyTimerIsZeroed`, `TestNZClampsNaNAndInf`).
6. **Bounded native-histogram memory**: `conn.lifetime` observations are externally driven (µs to hours), so native histogram bucket count must be capped and schema periodically reset per client_golang guidance (metrics.go comment).
7. **Push-loop timing**: each POST is bounded by an HTTP client timeout of one interval so a hung endpoint cannot stack requests (main.go `newMetricsPostClient` comment). Push loops tick at the configured interval, not faster on error.
8. **Goroutine lifecycle**: the runtime collector, Graphite push loop, and POST loop are deliberately process-lifetime (started at most once each at startup, no stop mechanism) — but there must be at most one of each, and none when metrics are disabled.
9. **Hostname resilience**: if `os.Hostname` fails, the JSON `hostname` field degrades to a usable fallback instead of failing registry construction (`TestNewRegistryHostnameFallback`).
10. **`LiveMetrics` is called at most once per registry** (duplicate registration would panic); `Dec` on a monotonic counter is a no-op, never a decrement.
11. **Actionable errors**: push failures logged through the injected `Logger` must identify the sink and the cause (dial vs. write vs. HTTP status).
12. **Graphite value rendering**: values print in shortest exact decimal form (integer-valued metrics without trailing `.0`), matching the historical bridge output.

## Edge cases a correct implementation must handle

- **Empty registry / zero-observation timer**: JSON is a valid (possibly empty) array; timer sub-metrics all render as 0, not NaN/error.
- **Quantile rank in the implicit +Inf bucket** (observation above the highest configured bucket): reported at the highest finite boundary; an explicitly gathered `+Inf` bucket must be handled identically (`TestHistogramQuantileInfBucketCap`, `TestHistogramQuantileExplicitInfBucket`).
- **Lowest-bucket interpolation** from a zero lower bound (durations are non-negative); q at exact bucket boundaries must be monotonic in q.
- **Graphite endpoint that accepts but never reads** (full TCP buffer): write deadline must fire; the flush returns an error within the timeout rather than wedging the loop.
- **Graphite connection must be closed after every flush** (success or error) — no fd leak across intervals.
- **Non-2xx POST responses** (including 3xx): treated as failure; response body must be drained/closed to avoid connection leaks.
- **Metric registered between snapshot's descriptor read and Gather** (or vice versa): degrade gracefully (skip/zero), never panic.
- **`--metrics-interval <= 0`**: rejected at startup with a message naming the flag and the offending value; must not create a `time.Ticker` with non-positive duration (which panics).
- **GC-pause accounting across collector ticks**: only pauses since the last collection are fed to the GC timer (no double-counting via the `PauseNs` circular buffer; handle >256 GCs between ticks).
- **Prefix flattening**: prefixes/names containing dots or dashes must map deterministically to the same Prometheus family name used at registration, or lookups in `Gather()` output silently miss (zero values on legacy sinks).

</details>

<details>
<summary><b>Proxy package (connection forwarding)</b> (7 raw findings)</summary>

# Behavioral Specification: Proxy Package (Connection Forwarding)

Scope: `proxy/proxy.go`, `proxy/semaphore.go`, `proxy/str.go` (tests: `proxy/*_test.go`), on the `next` branch where inline metrics code was replaced by integration with the new `metrics` package.

## Purpose

The `proxy` package is the data plane of ghostunnel: it accepts connections from a listener, enforces a TLS handshake with a configurable timeout, dials the backend via an injected `DialFunc`, optionally prepends a PROXY protocol v2 header, and fuses the two connections bidirectionally until both sides close. It also implements connection-count limiting, graceful shutdown/draining, and per-connection metrics recording.

## Documented behavior

1. **Handshake is forced before forwarding.** The TLS handshake is explicitly forced (not left to first read/write) so its timeout is controlled and unauthenticated clients cannot hold open half-open connections forever; the handshake verifies the client cert and authorization before any data flows (comment on `forceHandshake`, `proxy/proxy.go:449-454`; `--connect-timeout` flag help, `main.go:133`: "Timeout for establishing connections, handshakes", default 10s).
2. **Connection-count limiting.** `--max-concurrent-conns` (default 0 = infinite, `main.go:136`) caps simultaneous proxied connections; excess connections wait for a slot rather than being handled (integration test `tests/test-server-max-concurrent-conns.py`: "limits the number of simultaneous connections"; unit test `TestMaxConcurrentConns`). With the limit unset, the `unlimitedSemaphore` must never block, but must still respect context cancellation — `Acquire` returns `ctx.Err()` (`proxy/semaphore.go:30-32`; `TestUnlimitedSemaphoreAcquireWithCanceledContext`).
3. **Graceful shutdown sequence** (`docs/networking/graceful-shutdown.md`): on `Shutdown()` the proxy closes the listener and stops accepting new connections; established connections continue to flow until both sides close normally; connections mid-handshake or mid-dial are canceled rather than drained; `Wait()` blocks until listener closed AND connections drained. `Wait()` is documented safe to call before/concurrently with `Accept()` (`proxy/proxy.go:308-312`). Force-exit after `--shutdown-timeout` (default 5m, `main.go:132`) is main's job, exit code 1 vs 0 on clean drain.
4. **Multiple `Shutdown()` calls are safe** (test `TestMultipleShutdownCalls`) — idempotent, no panic on double listener close.
5. **Accept-error backoff.** Persistent `Accept()` errors trigger exponential backoff starting ~5ms, doubling to ~1s cap (mirrors `net/http.Server.Serve`; comment `proxy/proxy.go:316`, tests `TestAcceptErrorBackoff`). `Shutdown()` must promptly interrupt the backoff sleep (`TestAcceptErrorBackoffShutdownInterrupts`). Accept errors are logged only when the `LogConnectionErrors` flag is set (`TestAcceptErrorLogged`, `TestAcceptErrorNotLoggedWhenFlagDisabled`; integration test `test-server-quiet-conn-errs.py`).
6. **PROXY protocol v2** (`docs/networking/proxy-protocol.md`): in mode `conn`, header carries original client src IP/port and the local address of the accepted connection; address family auto-detected (IPv4/IPv6/`UNIX_STREAM`; `TestTransportProtocol`, `TestProxyProtocolSuccessIPv6`). Mode `tls` adds `PP2_TYPE_SSL` (client-flags byte with `0x01` always set, verify result always 0), `PP2_SUBTYPE_SSL_VERSION`, plus `PP2_TYPE_AUTHORITY` (SNI) and `PP2_TYPE_ALPN` when present. Mode `tls-full` additionally sets cert flags `0x02|0x04` and emits `PP2_SUBTYPE_SSL_CN` (omitted for empty CN) and `PP2_SUBTYPE_SSL_CLIENT_CERT` (DER). In `tls` mode cert flags/details are never sent even if a client cert was presented (`TestBuildSSLTLV`, `TestBuildTLVs`, `TestProxyProtoHeader*`). The header is written before any application data (`docs/networking/proxy-protocol.md:53-54`).
7. **PROXY header write failure closes the backend connection** rather than leaking it or forwarding data without the header (`TestProxyProtocolWriteFailureClosesBackend`).
8. **Half-close handling.** When one side terminates, the other side is closed after `--close-timeout` (default 1s; zero = immediate closure, `main.go:134`). One-directional EOF propagates as `CloseWrite`/`CloseRead` on TCP and UNIX conns; on conn types without half-close support the helpers must not panic (`closeRead`/`closeWrite`; tests `TestCloseRead/Write{TCP,Unix,NonTCP}Connection`). Integration tests `test-*-handles-{client,server}-closes-connection[-unix].py`: when either end disconnects, the other end's connection is torn down too.
9. **Max connection lifetime.** `--max-conn-lifetime` (default 0 = infinite, `main.go:135`) forcibly terminates connections post-handshake after the given duration, even if hung (`tests/test-server-max-conn-lifetime.py`: "Simulates a hanging connection, waits for timeout").
10. **Backend dial failure** must close the client connection and count an error, not hang the client (`TestBackendDialError`, `TestAbortedConnection`).
11. **ACME TLS-ALPN-01 challenge connections are never forwarded to the backend** — a connection that negotiated the ACME challenge ALPN protocol is a validator probe; the relaxed ClientAuth used for it must not authorize application data (comment `proxy/proxy.go:436-440`; `TestACMEChallengeNotForwardedToBackend`).
12. **Metrics** (`docs/networking/metrics.md`): the package records `accept.total` (every accepted attempt), `accept.success` (established), `accept.error` (failed attempts), `accept.timeout` (handshake timeouts), `conn.open` (gauge-like counter incremented on open, decremented on close), `conn.timeout` (data-transfer timeouts), `conn.handshake` (timer) and `conn.lifetime` (timer). These names are exported surface and must not change (`TestLiveMetricsRegisterCanonicalNames`).
13. **Metrics injection seam.** `New(..., nil)` records to a package-owned default registry (historical behavior); passing `metrics.NilMetrics()` yields no-op handles that skip collection entirely on the hot path (`proxy/proxy.go:50-56,252-257`; `TestNewMetricsWiring`, `TestNilMetricsAreNoOps`).
14. **NilMetrics must not swallow connections.** The connection handler must not be routed through `Timer.Time(fn)` — a no-op Timer's `Time()` never runs `fn`, which would silently drop every connection; `UpdateSince` is used instead (comment `proxy/metrics_test.go:30-35`; regression test `TestNilMetricsProxyForwardsData`).
15. **Connection logging** is conditional on flags: per-connection open/close messages with byte counts and duration can be suppressed (`TestLogConnectionMessageDisabled`, `TestLogConditional`; integration test `test-server-quiet-conn-logs.py`). Byte counts are humanized (`bytesWithUnit`, `TestBytesWithUnit`) and peer cert info is included where available (`peerCertificatesString`).

## Reasonable expectations

1. **Fail closed.** Any error before the fuse (handshake failure, handshake timeout, authorization failure, backend dial failure, PROXY header write failure) MUST close both ends that were opened and MUST NOT forward any client data to the backend.
2. **No fd/goroutine leaks.** Every accepted connection must reach a state where both the client and backend conns are closed exactly once, and both copy goroutines exit — including on error paths, timeouts, and `--max-conn-lifetime` expiry. `Wait()` returning implies zero live connection goroutines.
3. **Metrics accuracy under concurrency.** For every accepted connection, `accept.total` increments exactly once; exactly one of `accept.success` or `accept.error` (or timeout counting) follows; `conn.open` is incremented exactly once per open and decremented exactly once per close on ALL exit paths (including handshake failure, dial failure, ACME probe, semaphore-acquire failure), so it never drifts negative or leaks upward. Invariants must hold under concurrent connections (counters must be safe from multiple goroutines).
4. **Semaphore balance.** Every successful `Acquire` is matched by exactly one `Release` on every exit path; a failed/canceled `Acquire` must NOT be Released. A blocked `Acquire` must be interruptible by shutdown (context cancellation) so draining is not prevented by queued waiters.
5. **Shutdown races.** `Shutdown()` concurrent with in-flight `Accept()`/handshakes must not panic or deadlock; the closed-listener error from `Accept` must be recognized as shutdown, not treated as a persistent accept error (no backoff loop, no spurious error log after clean shutdown).
6. **Error classification.** Timeout errors (`net.Error.Timeout()`) and expected closed-connection errors (`use of closed network connection`, EOF, ECONNRESET, EPIPE) must be distinguished from real errors so half-closed teardown is not logged as failure and `conn.timeout` counts only genuine data-transfer timeouts (`TestIsTimeoutError`, `TestIsClosedConnectionError`, `TestCopyDataErrorClassification`).
7. **Byte accounting.** `copyData` must return bytes written even when the copy ends in an error, so logged forwarded/returned counts are accurate (`TestCopyData`).
8. **Deadlines don't corrupt live traffic.** `setDeadline`/close-timeout logic applied when one direction finishes must not prematurely kill the other direction while it is still actively transferring within the timeout window.
9. **Handshake timeout counts as `accept.timeout`** and produces an actionable log line (distinguishable from cert rejection), since operators use this to detect non-TLS clients hitting the listener.
10. **`forceHandshake` on a non-TLS conn** (client mode, or misconfiguration) must be a safe no-op or clean error, not a panic (`TestForceHandshakeNonTLSConn`).

## Edge cases a correct implementation must handle

1. Client connects and immediately disconnects (before/during handshake) — counted as error/timeout, no leak, backend never dialed or dialed conn closed.
2. Backend dial succeeds but PROXY header write fails — backend conn closed, client conn closed, error counted (test-pinned behavior).
3. TLS conn with no SNI and no ALPN — TLV list omits `PP2_TYPE_AUTHORITY`/`PP2_TYPE_ALPN` rather than emitting empty values.
4. `tls-full` mode with a client cert whose CN is empty — `PP2_SUBTYPE_SSL_CN` omitted, DER cert still sent; no client cert at all — cert flags unset, cert sub-TLVs omitted.
5. UNIX-socket listener with PROXY protocol — `UNIX_STREAM` family with socket paths; conn types that are neither TCP nor UNIX — `closeRead`/`closeWrite`/`transportProtocol` degrade gracefully.
6. Both sides close simultaneously — double-close of a `net.Conn` and concurrent `CloseWrite` must not error-log spuriously or double-decrement `conn.open`.
7. `Shutdown()` called before `Accept()` ever runs, or called twice — `Wait()` still returns (documented on `Wait`, `TestMultipleShutdownCalls`).
8. Listener returns a persistent non-temporary error (e.g. EMFILE) — backoff caps at ~1s, no CPU spin, recovery resumes accepting when the error clears.
9. `--max-concurrent-conns` saturated at shutdown — queued waiters canceled, in-flight fused connections drain normally.
10. Very long-lived connection spanning a shutdown — data continues until both sides close; only the external `--shutdown-timeout` force-exits it.
11. ACME TLS-ALPN-01 probe under a semaphore limit — the probe must release its slot and not count as a successful proxied connection.
12. IPv6 client addresses in the PROXY header (`TestProxyProtocolSuccessIPv6`) and wildcard listen addresses (destination = specific interface address, per `docs/networking/proxy-protocol.md:70-72`).

</details>

<details>
<summary><b>Main / CLI, lifecycle, status server</b> (5 raw findings)</summary>

# Spec: Main / CLI, Lifecycle, Status Server (ghostunnel)

## Purpose

The `main` package is ghostunnel's entry point: it parses and validates CLI flags (kingpin), dispatches to server mode (TLS listener → plain target) or client mode (plain listener → TLS target), and owns process lifecycle — signal handling, graceful shutdown, certificate/policy hot-reload, the optional status/metrics HTTP endpoint, metrics push sinks, TLS version/cipher configuration, and Linux Landlock sandboxing.

## Documented behavior

1. **Two subcommands** — `server` and `client` — each with required `--listen` and `--target` flags accepting `HOST:PORT`, `unix:PATH`, and (for listen) `systemd:NAME`/`launchd:NAME` (main.go flag help; README "Socket Activation").
2. **Safe-address gating**: server `--target` and client `--listen` must be localhost/`127.0.0.1`/`[::1]`/unix unless `--unsafe-target`/`--unsafe-listen` is passed (flag help; `TestAllowsLocalhost`, `TestDisallowsFooDotCom`).
3. **Non-dialable targets rejected**: `systemd:`/`launchd:` targets are invalid in both modes; client `--target` must be `HOST:PORT`, not unix (`TestValidateServerTargetRejectsSystemd/Launchd`, `TestValidateClientTargetRejectsUnix`).
4. **Exactly one credential source** (keystore / cert+key / keychain / workload API / ACME(server) / disable-auth(client)): zero → "at least one … required" error; more than one → "mutually exclusive" error. `--cert`/`--key` must be set together unless PKCS#11 supplies the key (`validateServerCredentials`, `validateClientCredentials`, `validateCertKeyPair`; tests/test-mutually-exclusive-{server,client}-flags.py, test-keystore-vs-disable-authentication-client-flags.py).
5. **Server access control required**: at least one of `--allow-{all,cn,ou,dns,uri}`, OPA flags, or `--disable-authentication`. `--allow-all` and `--disable-authentication` are each mutually exclusive with other access flags; `--allow-policy`/`--allow-query` must be used together but may combine (OR) with SAN flags (`validateServerAccessControl`, `validateServerOPA`; `TestServerFlagValidation`, test-server-allow-opa-with-flags.py).
6. **Cross-mode flag validation**: `--enable-pprof` and `--enable-shutdown` require `--status`; `--metrics-url` and `--target-status` must start with `http://` or `https://`; `--connect-timeout` must be nonzero (`validateFlags`; `TestFlagValidation`).
7. **`--status` shapes**: `[http(s)://]HOST:PORT`, `unix:PATH`, `systemd:NAME`, `launchd:NAME`. Scheme prefixes are only valid for TCP; unix/systemd/launchd status listeners always serve plain HTTP (`validateStatusAddress`; `TestValidateStatusAddress`; docs/networking/metrics.md).
8. **Status port TLS**: serves HTTPS by default using the same certificate as the proxy; `http://` prefix forces plain HTTP; on TCP it also falls back to plain HTTP if the cert source cannot act as a server (e.g. client mode with `--disable-authentication`) (docs/networking/metrics.md).
9. **Endpoints**: `/_status` (JSON with `backend_ok`, `backend_status`, `backend_error`; HTTP 503 when the backend check fails), `/_metrics` (JSON by default, Prometheus with `?format=prometheus`), `/_metrics/json`, `/_metrics/prometheus` (native client_golang exposition), `/debug/pprof/*` only with `--enable-pprof`, `/_shutdown` only with `--enable-shutdown` — POST triggers graceful shutdown, any other method returns 405 (docs/networking/metrics.md; tests/test-server-metrics-endpoint.py, test-{client,server}-shutdown-http.py).
10. **Backend healthcheck**: server mode defaults to a raw TCP check against `--target`, overridable with `--target-status=URL` (HTTP GET expecting 200); client mode performs a full TLS connection to the target (docs/networking/metrics.md; status.go comments; `TestStatusTargetHTTP2XX/Non2XX/WithError`; tests/test-server-target-status.py).
11. **Shutdown**: SIGTERM/SIGINT (Unix), Interrupt/SCM stop (Windows), or POST `/_shutdown` trigger graceful shutdown: status flips to "stopping", status server shuts down best-effort, listener closes, in-flight connections drain, process exits 0; after `--shutdown-timeout` (default 5m) it force-exits with code 1 (docs/networking/graceful-shutdown.md; signals.go comments; tests/test-*-shutdown-{sigterm,http,timeout}.py, test-service-scm-graceful-shutdown.py).
12. **Reload**: SIGHUP/SIGUSR1 (never shutdown) or `--timed-reload=DURATION` reload certificate, key, CA bundle, and OPA bundles; the new certificate is used for new connections only (README "Certificate Hotswapping"; `TestSignalHandlerReloadAndShutdown`; tests/test-*-reloads-keystore.py, test-server-ca-bundle-reload.py).
13. **Failed reload keeps old state**: a broken certificate, CA bundle, or OPA bundle on reload MUST leave the previous config serving and MUST NOT crash the process (tests/test-{client,server}-reload-broken-certificate.py, test-server-reload-broken-cabundle.py, test-server-opa-reload-fail.py).
14. **Metrics gating**: metrics are collected only when at least one sink exists — the pull surface (`--status`) or a push reporter (`--metrics-graphite`, `--metrics-url`); with no sinks the proxy gets no-op handles and no background collection goroutines run. A push sink alone (graphite without `--status`) MUST still enable collection (`setupMetrics` doc comment; tests/test-server-metrics-graphite-only.py).
15. **Metrics push**: `--metrics-graphite=ADDR` (raw TCP) and `--metrics-url=URL` (HTTP POST, JSON) report every `--metrics-interval` (default 30s) with names prefixed by `--metrics-prefix` (default `ghostunnel`) (flag help; docs/networking/metrics.md; tests/test-{client,server}-metrics-{graphite,bridge}.py).
16. **Push-sink failure is non-fatal**: a `--metrics-url` receiver returning non-2xx (or being down) MUST NOT break proxying; the push loop keeps retrying, and each POST is bounded by a timeout so a hung endpoint cannot back up the loop (tests/test-server-metrics-url-error.py docstring; `newMetricsPostClient` comment).
17. **Port conflicts fail startup**: if `--listen` or `--status` cannot bind, the process exits nonzero with an error (tests/test-*-listen-port-conflict.py, test-{client,server}-status-port-conflict.py).
18. **TLS config**: `--cipher-suites` (default `AES,CHACHA`) is validated at flag-parse time via the same resolver used at runtime; unsafe suites require `--allow-unsafe-cipher-suites`; `--max-tls-version` accepts `TLS1.2`/`TLS1.3` and invalid values error out; server config requires client certs by default (tls.go comments; `TestResolveCipherSuites`, `TestValidateCipherSuitesMatchesBuildConfig`, `TestParseTLSVersion`; tests/test-server-max-tls-version.py).
19. **Logging**: `--quiet` accepts `all|conns|conn-errs|handshake-errs` (repeatable); `--quiet=all` disables all log output; `--syslog`/event log via platform system logger, with a graceful error if unavailable (flag help; `TestInitLoggerQuiet`, `TestInitSystemLoggerError`).
20. **Landlock (Linux)**: enabled by default in best-effort mode — setup failure logs a warning and continues; skipped entirely with PKCS#11; disabled by `--disable-landlock` (README "Landlock Support"; run() comments; landlock_test.go; tests/test-server-landlock-ssl-cert-file.py).
21. **systemd integration**: on Linux the process sends readiness/reloading/stopping/watchdog notifications; non-Linux stubs must be no-ops that never panic (status_linux.go; `TestHandleWatchdogCallsSystemd`, `TestNonLinuxNotifyHelpersDoNotPanic`).
22. **ACME**: `--auto-acme-cert` requires `--auto-acme-email` and `--auto-acme-agree-to-tos`, with specific error messages for each omission (`validateServerACME`; `TestServerValidateFlagsACMEMissingEmail/TOS`).
23. **All exits go through `exitFunc`** so coverage counters flush on signal-triggered exits (coverage builds) and exits stay testable (main.go comment; coverage_enabled.go).

## Reasonable expectations

1. Every flag-validation failure MUST occur before any listener is bound or background goroutine started, and the error message MUST name the offending flag(s).
2. Any error after resources are acquired (status listener up, reload/metrics goroutines started) MUST close listeners and stop those goroutines on the way out — no dangling accept loops, tickers, or signal handlers after `run()` returns an error.
3. `statusHandler` state (backend status, reload timestamps) is shared between HTTP handlers, the signal handler, and the reload loop; all access MUST be mutex-protected, and concurrent `/_status` requests must be race-free.
4. `/_status` MUST accurately track lifecycle: unhealthy before `Listening()`, reflect `Reloading()` during reload, and report stopping after shutdown is triggered.
5. The backend healthcheck MUST be bounded by a timeout (connect-timeout) so a hung backend cannot wedge status-handler goroutines or exhaust them under health-check polling.
6. Shutdown MUST be idempotent and non-blocking: concurrent triggers (signal + repeated `/_shutdown` POSTs) must not deadlock, double-close channels, or leak handler goroutines (shutdownHandler comment documents the non-blocking send requirement).
7. Reload (SIGHUP/timed) MUST never interrupt established proxied connections; only new connections see the new cert/policy.
8. Fail-closed: an error obtaining the TLS config source or compiling the OPA policy at startup MUST abort startup, never silently proceed without authentication.
9. Flag-parse-time cipher validation and runtime `tls.Config` construction MUST use a single shared resolver so accepted flags can never fail later at config-build time (tls.go comment states this invariant).
10. Exit codes: 0 for clean drain, 1 for shutdown-timeout force-exit, nonzero for startup errors — stable, since orchestrators and the integration harness depend on them.
11. The metrics registry is written from the connection hot path and read by push loops and HTTP handlers concurrently; it must be safe without slowing the hot path, and no-op handles must be genuinely free when no sink is configured.
12. The graceful-shutdown timer must fire even if the status HTTP server's own shutdown hangs (best-effort per signals.go comment).

## Edge cases a correct implementation must handle

1. `--status` on an already-bound port: clean nonzero exit, no half-started proxy.
2. `--status unix:PATH` (or systemd:/launchd:) combined with an `http(s)://` prefix: rejected at validation.
3. `--metrics-url` endpoint down, returning non-2xx, or hanging: proxy traffic unaffected; push loop retries next interval.
4. Graphite as the *only* sink (no `--status`): metrics still collected and pushed.
5. SIGHUP arriving mid-shutdown, or shutdown signal arriving during a reload: no deadlock, shutdown wins.
6. Repeated `/_shutdown` POSTs after shutdown already requested: handler returns without blocking (buffered channel full).
7. `GET /_shutdown` → 405; `/_shutdown` requested without `--enable-shutdown` → not served.
8. Reload with corrupt cert/key, corrupt CA bundle, or bad OPA bundle: old config keeps serving; error logged; process stays up.
9. `--timed-reload` of zero/unset: no reload ticker goroutine spun up.
10. Client `--proxy` set: target hostname resolution skipped (equivalent to `--skip-resolve`) since the proxy resolves it.
11. Shutdown timeout expiring with connections still open: exit code 1 and (in coverage builds) counters flushed via exitFunc hook.
12. Landlock unsupported by the running kernel: warning logged, startup continues.
13. Windows: `ghostunnel service status` for a nonexistent service exits nonzero (tests/test-service-status-not-found.py); SCM stop drains like SIGTERM.
14. Status port falling back from HTTPS to HTTP (no server-capable cert): endpoints must remain functional, not error.

</details>

<details>
<summary><b>Certloader (certificate sources & hot reload)</b> (6 raw findings)</summary>

# Behavioral Specification: Certloader (certificate sources & hot reload)

## Purpose

The `certloader` package abstracts certificates and trust stores behind reloadable interfaces (`Certificate`, `TLSConfigSource`, `TLSClientConfig`/`TLSServerConfig`) so that ghostunnel can serve TLS from PEM, PKCS#12, JCEKS, PKCS#11 (HSM), SPIFFE Workload API, ACME, and macOS/Windows keychain sources uniformly (certloader/doc.go). Its central promise is runtime credential reloading without dropping existing connections, plus per-connection retrieval of the current cert/trust store via cached `tls.Config` objects that are safe for concurrent use.

## Documented behavior

1. **Supported sources.** `--keystore` accepts combined PEM or PKCS#12 (auto-detected); `--cert`/`--key` accept separate PEM files (always parsed as PEM, no auto-detection); JCEKS/JKS is supported via `--keystore` with a mandatory `--storepass`; PKCS#12 password is optional (main.go flags 117-120; docs/certificates/formats.md).
2. **Format auto-detection.** Keystore format is detected first by file extension (`.pem`, `.crt`, `.p12`, `.pfx`, `.jceks`, `.jks`), falling back to inspection of leading magic bytes for PEM, PKCS#12, JCEKS, and DER (formats.md "Format Auto-Detection"; `ErrUnknownFormat` in certloader/errors.go; TestFormatDetectionDERMagicBytes, TestReadCertsFromStreamUnknown in decode_test.go).
3. **Chain order.** For PEM, the leaf certificate must come first, followed by intermediates; the private key may appear anywhere in a combined PEM keystore (formats.md).
4. **Reload triggers and scope.** SIGHUP/SIGUSR1 (Unix) or `--timed-reload DURATION` (all platforms) re-reads the certificate/key, CA bundle, and OPA policies from disk. Once a reload succeeds, only new connections use the new configuration; existing connections are unaffected (README "Certificate Hotswapping"; docs/certificates/reloading.md).
5. **Failed reload keeps old state.** `Certificate.Reload()` and `TLSConfigSource.Reload()` are documented: "If reloading failed, the old state is kept" (certificate.go, tlsconfig.go doc comments). A corrupted cert file or CA bundle between reloads must not stop serving with the previously loaded material (tests/test-server-reload-broken-certificate.py, test-server-reload-broken-cabundle.py, test-client-reload-broken-certificate.py; TestKeystoreReloadErrorKeepsOldCertificate, TestKeystoreCertificateReloadBadCABundle).
6. **PKCS#11 reload semantics.** Only the certificate is reloaded from disk; the HSM private key is assumed unchanged and the new cert must still match it (README; docs/certificates/hsm-pkcs11.md).
7. **Keychain reload semantics.** Reload re-queries the OS store using the same identity/issuer/serial criteria; candidates are matched by CN, serial, or issuer, sorted by NotAfter descending (newest wins), identities with chain errors are skipped, and no-match is an error (certstore_reload_test.go: TestReload_MatchByCommonName/SerialNumber/IssuerOnly, TestReload_SortsByNotAfterDescending, TestReload_SkipsIdentityWithChainError, TestReload_NoCandidatesFound).
8. **SPIFFE Workload API.** Enabled via `--use-workload-api` or `--use-workload-api-addr`/`SPIFFE_ENDPOINT_SOCKET`; certificates and trust bundles are pushed by the provider and picked up automatically with no manual reload (docs/certificates/spiffe-workload-api.md; TestWorkloadAPISVIDRotation). In client mode SPIFFE verification replaces hostname verification; `--verify-uri` pins the peer ID. With `--disable-authentication` the client sends no certificate (TestWorkloadAPIClientDisableAuth, TestCachedSPIFFEConfigClientAuthBranch).
9. **ACME.** Server mode only (`ErrACMENotSupportedClient`). Initial issuance retries up to 5 times with exponential backoff (5s start, 2min cap) and exits on exhaustion (docs/certificates/acme.md "Startup Retry Behavior"; TestACMEInitialIssuanceSingleAttemptNoRetry, TestACMEInitialIssuanceRetriesExhausted). Renewal is handled by certmagic in the background; a manual reload only refreshes the CA bundle (reloading.md; TestACMETLSConfigSourceReloadTrustStore).
10. **ACME TLS-ALPN-01 under mTLS.** A handshake offering exactly `["acme-tls/1"]` with non-empty SNI is exempted from client-cert requirement; the exemption pins ALPN, disables session resumption, and any connection negotiating `acme-tls/1` is closed without dialing the backend (acme.md "Renewal Under mTLS"; TestACMETLSConfigRelaxesClientAuthForACMEChallenge; tests/test-server-acme-tls-alpn-renewal.py). `NextProtos` must contain `acme-tls/1` exactly once, never growing across calls (TestCachedACMENextProtosStable).
11. **CA bundle.** `--cacert` is a PEM bundle; if omitted, the system trust store is used (main.go flag 121; TestLoadTrustStoreSystemRoots). An unparsable bundle yields `ErrNoCACerts` (TestLoadTrustStoreInvalid).
12. **Config getters are concurrency-safe.** `GetClientConfig()`/`GetServerConfig()` on the returned config objects are documented "safe to call concurrently" (tlsconfig.go).
13. **JCEKS decoding.** Supports RSA/ECDSA/Ed25519 key recovery, rejects wrong passwords and unsupported algorithms, enforces size limits on cert/key entries, validates header version and modified-UTF-8 strings (jceks_test.go: TestRecover*, TestWithMaxCertificateBytes, TestParseHeaderVersionMismatch, TestReadModifiedUTF8*).

## Reasonable expectations

1. **Atomic swap.** A reload must atomically publish the new cert+truststore pair (e.g. one atomic pointer store); a concurrent reader must never observe a torn state, a nil certificate, or a mixed old-cert/new-pool combination (TestCachedCertServerConfigConcurrentReload comment: "never a torn or nil value"; run under -race).
2. **Cache correctness after reload.** Cached `tls.Config` objects must be rebuilt exactly once per reload and reflect the new trust store on the next call; without an intervening reload, repeated calls must return the identical pointer (TestCachedCertServerConfigPointerIdentity, TestCachedCertServerConfigReloadVisibility, TestCachedACMEServerConfigReloadVisibility).
3. **Zero steady-state allocations.** `GetServerConfig()`/`GetClientConfig()` in steady state must not allocate — they sit on the per-connection accept path (TestCachedCert*ZeroAllocs, TestCachedACMEServerConfigZeroAllocs, TestCachedSPIFFEConfigZeroAllocs, certtlsconfig_bench_test.go).
4. **No mutation of shared configs.** The `base *tls.Config` passed to `GetClientConfig`/`GetServerConfig` is cloned, never mutated; cached configs handed to callers must not be modified in place after publication (interface doc, tlsconfig.go). Per-call state (e.g. appending to `NextProtos`) must not leak into the shared config.
5. **SPIFFE build-once cache.** The SPIFFE source has no invalidation key (X509Source self-maintains), so its config is built once and cached forever — the single build must be correct because a wrong config never self-corrects (spiffe_cached_config_test.go header comment).
6. **Fail-closed on load errors.** Initial load failures (bad file, wrong password, unknown format, unmatched key/cert, empty CA bundle) must return an error and prevent startup, with actionable messages (tests/test-invalid-certificate.py, test-invalid-cacert.py; sentinel errors in errors.go). A source that cannot serve (no private key, client-only) must report `CanServe() == false` and return `ErrNotServerCert` from `GetServerConfig` (TestCertTLSConfigSourceCanServeWithoutPrivateKey, TestACMETLSConfigSourceCanServe).
7. **Resource lifecycle.** SPIFFE sources must be closeable, releasing the Workload API connection and any watch goroutines (TestSpiffeTLSConfigSourceClose); dialers must honor context cancellation and timeouts and close raw connections on handshake failure (dialer_test.go: TestDialWithDialerContextCancellation, TestDialWithDialerTimeout, TestDialWithDialerRawConnFailure). Listeners wrapping a source must serve reloaded configs on subsequent accepts and close cleanly (TestListenerConfigReload, TestListenerClose).
8. **ACME cert temporarily unavailable** must surface `ErrACMECertUnavailable` rather than a nil-pointer panic when the managed certificate is not (yet) present.
9. **Reload errors must be observable** (logged / surfaced to the caller) even though serving continues with old state — silent reload failure of an expiring cert is an outage waiting to happen.

## Edge cases a correct implementation must handle

1. Keystore file with unrecognized extension but valid magic bytes (PEM/PKCS#12/JCEKS/DER); truly unknown content yields `ErrUnknownFormat`, not a panic.
2. Combined PEM with the key before, between, or after certificates; PEM with zero certificates; garbage between PEM blocks (TestReadPEMNoCertsFound, TestReadX509ParseCertificateError).
3. PKCS#12 with empty password vs. wrong password; Ed25519 keys in PKCS#12 (TestReadPKCS12ED25519) and JCEKS (TestRecoverED25519Key).
4. JCEKS with bad magic, wrong version, wrong password, oversized entries, trusted-cert-only entries, and malformed modified-UTF-8 alias names (including surrogate pairs, bare NUL, truncated multi-byte sequences) — all rejected without panic.
5. Cert file replaced with a cert that does not match the key (or vice versa) between reloads: reload fails, old pair keeps serving, split `--cert`/`--key` included (tests/test-server-reloads-split-cert-key.py).
6. CA bundle deleted or corrupted between reloads: trust store reload fails independently of cert reload; previous pool keeps serving.
7. Concurrent `Reload()` racing with per-connection `GetCertificate`/`GetServerConfig` calls (many goroutines; must be race-free and never yield nil).
8. Keychain: multiple matching identities (pick newest NotAfter), identities whose chain retrieval errors mid-sort, both identity and issuer filters set but only one matches (no match), and empty identity list.
9. SPIFFE: Workload API unreachable at startup (creation error, not hang), invalid address string, source used after Close, SVID rotation mid-traffic.
10. ACME: `--auto-acme-testca` overrides `--auto-acme-ca`; CA bundle supplied alongside ACME (client verification pool) including empty and invalid bundles (TestNewACMETLSConfigSourceEmptyCABundle/InvalidCABundle); challenge ClientHello with `acme-tls/1` plus another ALPN or missing SNI treated as a normal (mTLS-required) client.
11. `--disable-authentication` client mode uses a no-op certificate source that still provides a trust store and never sends a client cert (no_cert_test.go).

</details>

<details>
<summary><b>Auth, policy (OPA), wildcard matching</b> (0 raw findings)</summary>

# Behavioral Spec: Auth, OPA Policy, and Wildcard Matching (ghostunnel)

## Purpose

This area implements ghostunnel's access control path: verifying peer X.509 certificates against allow/verify flags (CN, OU, DNS/IP/URI SANs), evaluating OPA/Rego policies against the peer certificate, and compiling/matching wildcard URI patterns. It is invoked on every TLS handshake (server mode: `ACL.VerifyPeerCertificateServer`; client mode: `ACL.VerifyPeerCertificateClient`) and is the security boundary of the proxy — errors here must fail closed on the server side.

## Documented behavior

1. **Server mode requires at least one access control flag.** Startup MUST fail with an actionable error if none of `--allow-all`, `--allow-cn`, `--allow-ou`, `--allow-dns`, `--allow-uri`, `--allow-policy`, or `--disable-authentication` is given (README "Server mode"; main.go validation: "at least one access control flag ... is required").
2. **OR semantics between allow flags.** Multiple certificate-field flags are a logical disjunction: a client is allowed if at least one flag matches. `--allow-policy`/`--allow-query` is also OR'd with the field flags (README lines 147–153; docs/security/access-flags.md; auth/auth.go ACL doc comment: "These options are disjunctive"; integration test `test-server-allow-opa-with-flags.py`: client1 allowed by policy only, client2 by `--allow-cn` only, both must connect).
3. **`--allow-all` is mutually exclusive with other access flags** and grants access to any peer with a valid certificate (main.go: "--allow-all is mutually exclusive with other access control flags"; access-flags.md; `TestAuthorizeAllowAll`).
4. **`--disable-authentication` is mutually exclusive with the rest**; no client certificate is required at all (access-flags.md; `test-server-disable-authentication.py`).
5. **Exact string match for CN, OU, DNS SAN; exact IP match for the hidden `--allow-ip`.** No wildcarding, no DNS lookups (access-flags.md; `TestAuthorizeAllowCN/OU/DNS/IP`, `TestVerifyReject{CN,OU,DNS,IP}`).
6. **URI SAN flags support `*` and `**` wildcards** via the wildcard package: `--allow-uri=spiffe://ghostunnel/*` matches `spiffe://ghostunnel/client1` etc. (access-flags.md; `TestAuthorizeAllowURI`, `test-server-allow-uri-san.py`).
7. **Wildcard grammar** (wildcard/matcher.go package doc): patterns are `/`-separated segments; `*` matches any non-empty string not containing the separator and may only be a whole segment (a `*` inside a literal segment is a compile error); `**` matches anything including separators and may only appear at the end of a pattern (bare `**` matches everything, documented special case). A single trailing separator is optional on both input and pattern: `foo` ≡ `foo/`, and `test://foo/bar` matches iff `test://foo/bar/` matches (`TestTrailingSeparatorEquivalence`, `TestBareDoubleWildcard`, `TestMatchingWithDouble`).
8. **Invalid wildcard patterns MUST be rejected at startup**, not silently accepted: an empty or malformed `--allow-uri` pattern causes ghostunnel to exit non-zero (`test-server-invalid-uri-pattern.py`; wildcard errors `errEmptyPattern`, `errInvalidWildcard`, `errInvalidDoubleWildcard`; `TestInvalidPatterns`, `TestCompileList` rejects the whole list on one bad pattern).
9. **Regex metacharacters in patterns and separators are literal.** `.`, `|`, `+`, `?`, `\`, `^`, `]` etc. in literal segments or as custom separators must never be interpreted as regex syntax (`TestMatchingWithMetaChars`, `TestCompileWithSeparatorMetaChars` — including the `\b`/`\d` character-class escape hazards called out in test comments).
10. **`--allow-policy`/`--allow-query` must be used together** (main.go: "--allow-policy and --allow-query have to be used together"; same for `--verify-policy`/`--verify-query`).
11. **OPA policies load from a local bundle (or a legacy raw `.rego` file, treated as Rego V0)**; a policy that fails to load at startup MUST cause a non-zero exit (`test-server-invalid-opa.py`, `test-client-invalid-opa.py`, `TestPolicyInitFail`; access-flags.md Notes).
12. **OPA "allow" convention:** access is granted only if the query produces exactly one result with a single expression whose value is `true` and no variable bindings (access-flags.md Notes; `TestAuthorizeOPAAccept*`/`Reject*`). The peer certificate is exposed as `input.certificate` (x509.Certificate structure).
13. **Policy evaluation timeout equals the connection timeout** (`--connect-timeout`): a policy that runs longer MUST fail the connection, i.e. deny (access-flags.md Notes; `test-server-opa-slow-policy.py`; ACL.OPAQueryTimeout comment).
14. **Policies hot-reload** via `--timed-reload` or SIGHUP just like certificates (access-flags.md; `Policy` interface with `Reload()`; `TestPolicyReloading`). A failed reload MUST leave the previously loaded policy in effect and keep serving traffic (`test-server-opa-reload-fail.py`, `TestPolicyReloadFail`; loader.go only swaps `cachedPolicy` on success).
15. **Server side fails closed; client side fails open on empty ACL.** `VerifyPeerCertificateServer` with an empty ACL rejects all clients (doc comment: "fails closed"; `TestAuthorizeReject`). `VerifyPeerCertificateClient` with an empty ACL allows all servers, because standard hostname verification has already run in crypto/tls (doc comment: "fails open"; `TestVerifyAllowEmpty`); when any verify flag is set, at least one must match (`TestVerifyReject*`).
16. **Client mode always performs hostname verification** in addition to any verify flags; `--override-server-name` redirects it; with `--use-workload-api` it is replaced by SPIFFE X509-SVID verification, pinned with `--verify-uri` (access-flags.md "Client mode").
17. **A peer with no verified chains MUST be rejected** — authorization operates on `verifiedChains`, not raw certs (`TestAuthorizeNotVerified`, `TestVerifyNoVerifiedChains`).

## Reasonable expectations

1. **Fail-closed on any evaluation error (server).** An OPA eval error, timeout, or nil/undefined result MUST deny access, never grant it (`TestAuthorizeOPAEvalError`, `TestVerifyOPAEvalError`). No code path in `VerifyPeerCertificateServer` may return nil due to an error being swallowed.
2. **Only the leaf certificate's attributes grant access.** Matching must be done against `verifiedChains[i][0]` (the peer leaf), never against intermediates or CA certs in the chain.
3. **Concurrency safety of the shared policy.** `Eval` runs concurrently on many handshake goroutines while `Reload` may run from the signal/timer path; the cached prepared query swap must be atomic (loader.go uses atomic pointer ops) with no torn reads and no eval on a nil policy after successful `LoadFromPath`.
4. **Pattern compilation happens once at startup, matching is allocation-cheap and panic-free.** `Matches` must be safe for concurrent use (compiled `regexp` is), and `MustCompile` panics must be unreachable from user input paths (user flags go through `Compile`/`CompileList` which return errors).
5. **Denials must be deterministic and produce actionable error messages** naming which check failed (e.g. "client certificate not allowed"), suitable for handshake error logs; error text must not leak into over-broad matches.
6. **Eval must respect the passed context**: cancellation/deadline must abort policy evaluation promptly so a slow policy cannot pin handshake goroutines beyond the timeout (no goroutine leak per connection attempt).
7. **Mutual-exclusion and flag-pairing validation happens before listening** — misconfiguration must never result in a listener that silently allows everyone.
8. **No partial-application on bad config lists**: one invalid URI pattern or IP in a repeated flag must fail startup for the whole list, not skip the bad entry.

## Edge cases a correct implementation must handle

1. `*` MUST NOT match an empty segment (regex uses `[^sep]+`): `spiffe://host/*` must not match `spiffe://host/` or `spiffe://host`.
2. `*` MUST NOT cross a separator: `foo/*` does not match `foo/bar/baz` (`TestCompileWithSeparator`: "'*' should NOT cross the '.' separator").
3. `**` anywhere except pattern end is a compile error; `a/**` matches `a`, `a/`, and `a/b/c` (matcher regex makes the preceding separator optional).
4. Trailing-separator equivalence must be symmetric (pattern side and input side) and apply only to a *single* trailing separator — `foo//` is not `foo`.
5. Pattern equal to just the separator (`"/"`) must not be normalized into an empty pattern.
6. Custom separators that are regex metacharacters or character-class escapes (`.`,`|`,`+`,`?`,`*`,`]`,`\`,`^`,`b`,`d`,`w`,`s`) must be handled via proper quoting both inside and outside character classes.
7. Certificates with multiple OUs / multiple SANs: any single intersecting value grants access (intersection semantics, `TestAuthorizeOPAAcceptOneOU` vs `RejectAllOU` for the OPA analog).
8. OPA result sets that are empty, have multiple results, have bindings, or a non-boolean/false expression value must all be treated as deny (convention in access-flags.md Notes).
9. Reload race: a handshake in flight during `Reload` must evaluate against either the old or the new policy in full — never a mix or a nil pointer.
10. `.rego` suffix selects legacy V0 loading; anything else is loaded as a bundle — a bundle path that happens to fail must error, not fall back silently.
11. Empty `--allow-uri`/`--verify-uri` value ("") must be a startup error, not a match-nothing or match-everything pattern.
12. Client mode: verify flags are additional to hostname verification, never a replacement — a matching `--verify-cn` must not rescue a connection whose hostname verification failed (crypto/tls ordering guarantees this; the ACL code must not disable it).

Key files: /home/user/ghostunnel/auth/auth.go, /home/user/ghostunnel/policy/loader.go, /home/user/ghostunnel/policy/policy.go, /home/user/ghostunnel/policy/wrap.go, /home/user/ghostunnel/wildcard/matcher.go, /home/user/ghostunnel/docs/security/access-flags.md, /home/user/ghostunnel/main.go (flag validation), /home/user/ghostunnel/tests/test-server-*opa*.py, /home/user/ghostunnel/tests/test-server-invalid-uri-pattern.py.

</details>

<details>
<summary><b>Socket binding & platform certstore</b> (4 raw findings)</summary>

# Behavioral Spec: Socket Binding & Platform Certstore

## Purpose

The `socket` package parses listen/target address strings and opens listening sockets for all schemes ghostunnel documents: direct TCP, UNIX domain sockets, and socket activation via systemd (Linux) and launchd (macOS) (`socket/doc.go`). The `certstore` package provides a platform-abstracted `Store`/`Identity` interface over the macOS Keychain and Windows Certificate Store so `--keychain-identity`/`--keychain-issuer` can load hardware-backed TLS identities, with a stub on unsupported platforms.

## Documented behavior

1. **Address schemes.** `ParseAddress` MUST accept `HOST:PORT` (TCP), `unix:PATH`, `systemd:NAME`, and `launchd:NAME`, returning the network/address pair for each. Sources: flag help "Address and port to listen on (can be HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME)" (main.go:71,101,145); README "Socket Activation"; `TestParseAddress` (socket/net_test.go:27).
2. **TCP validation.** For `HOST:PORT` input, the host/port split MUST succeed (`net.SplitHostPort`) and, unless `skipResolve` is set, the address MUST resolve at parse time; otherwise an error is returned (`ParseAddress` doc comment, net.go:26-31; `TestParseAndOpenUnresolvable`, `TestParseAddressWithSkipResolve`).
3. **Listen-only schemes.** `systemd:` and `launchd:` are listen-only; `IsDialableNetwork` reports only `tcp` and `unix` as dialable, and `--target` help documents only `HOST:PORT` / `unix:PATH` (net.go:64-69; main.go:72,103). Passing an activation scheme as a target MUST be rejected, not silently mis-dialed.
4. **Status address.** `--status` additionally accepts `http://`/`https://` prefixes; `ParseHTTPAddress` strips the prefix and defaults to HTTPS when no prefix is present (net.go:71-87; main.go:145; `TestParseHTTPAddress`).
5. **TCP listeners use SO_REUSEPORT** so a new instance can bind while an old one drains (Open doc comment, net.go:92-93; README's overlapping-restart story).
6. **UNIX socket cleanup.** A UNIX listener opened by ghostunnel itself MUST unlink its socket file on close (`SetUnlinkOnClose(true)`, net.go:113-118; `TestOpenUnixSocketUnlinksOnClose`).
7. **Systemd activation by name.** `systemd:NAME` MUST select the inherited fd whose `FileDescriptorName` matches NAME. Exactly one socket per name is required: zero matches and >1 matches are distinct, descriptive errors naming the socket and count found (systemd_enabled.go:51-60; `TestSystemdSocketMultipleNames`, `TestSystemdSocketMultipleSocketsSameName`; tests/…systemd-socket-activation-error.py).
8. **Multiple named systemd sockets.** Because the activation library consumes `LISTEN_FDS` on first read, the listener map MUST be fetched once and cached so `--listen=systemd:a` and `--status=systemd:b` both work in one process (comment at systemd_enabled.go:29-33).
9. **Inherited unix sockets persist.** A systemd-inherited UNIX socket MUST NOT be unlinked when ghostunnel closes it — the path belongs to systemd (`TestSystemdInheritedUnixSocketNotUnlinkedOnClose`; tests test-client-systemd-unix-socket-persists.py). Contrast with behavior 6 for self-created sockets.
10. **Launchd activation.** `launchd:NAME` MUST call `launch_activate_socket` and require exactly one fd for the name, erroring with the name and count otherwise (launchd_enabled.go:34-57; test-client-launchd-socket-activation{,-error}.py).
11. **Platform gating with clear errors.** On non-Linux builds `systemd:` MUST fail with "systemd socket activation is only supported on linux"; on non-darwin/non-cgo builds `launchd:` fails analogously (systemd_disabled.go, launchd_disabled.go). Build tags: `linux` / `!linux`; `darwin && cgo` / `!darwin || !cgo` — the pairs MUST be exact complements so exactly one implementation compiles everywhere.
12. **Keychain identity selection.** `--keychain-identity` matches a certificate's CN **or** serial number; `--keychain-issuer` matches issuer CN; both together are a logical AND; among multiple matches the certificate with the latest NotAfter MUST be chosen (docs/certificates/keychain.md "Selecting a Certificate"; main.go:158-159; tests/test-server-keychain-identity-{darwin,windows}.py).
13. **Windows store search order.** Windows lookup searches the "MY" store at CURRENT_USER, then CURRENT_SERVICE, then LOCAL_MACHINE. CURRENT_USER MUST be openable (error otherwise); the other two are skipped without error if inaccessible (keychain.md "Which stores does Ghostunnel search?").
14. **Hardware-token filter.** `--keychain-require-token` (macOS only; main.go:161) MUST restrict `Identities(RequireToken)` to token/Secure-Enclave-backed identities (certstore.go:16-19; keychain.md "Secure Enclave and Hardware Tokens"). The flag MUST not be offered/effective on other platforms (main.go:161-165).
15. **Keychain flags gated by build support.** `--keychain-identity`/`--keychain-issuer` exist only when compiled with keychain support (`certloader.SupportsKeychain()`; main.go:156-158, version string at main.go:621), and validation treats them as one of the mutually-exclusive credential sources (main.go:344-347, 453-456).
16. **Keychain reload.** On SIGHUP/SIGUSR1 or `--timed-reload`, ghostunnel re-queries the keychain with the same criteria and picks up renewed certificates for subsequent connections (keychain.md "Certificate Reloading").

## Reasonable expectations

1. **Fail-closed startup.** Any parse or bind failure (bad address, unresolvable host, missing/ambiguous activation socket, unopenable keychain store) MUST abort startup with an actionable error naming the offending address/name — never fall back to a different address or an unauthenticated identity.
2. **No fd leaks.** `launchdSocket` MUST close the dup'd `os.File` after `net.FileListener` (it dups the fd) and free C allocations exactly once; error paths must not leak the C fd array or CString.
3. **Cgo memory safety (certstore).** Every CoreFoundation/CryptoAPI object obtained MUST be released exactly once, including on every error path; `Identity.Close()` and `Store.Close()` MUST be idempotent-safe to call after partial failures. `Signer()` MUST return `ErrUnsupportedHash` (not panic) for unsupported hash algorithms.
4. **Concurrency.** The systemd listener cache uses `sync.Once`; concurrent `Open` calls for different names MUST be race-free. A cached error MUST be returned consistently to all callers.
5. **Prefix parsing is anchored.** Scheme detection is prefix-based; `unix:`, `systemd:`, `launchd:` prefixes MUST be checked before host:port parsing so a path containing a colon is never misread as HOST:PORT. An empty name/path after the prefix should fail at Open with a clear error rather than binding something unintended.
6. **ParseAddress/Open contract.** Every (network, address) pair that `ParseAddress` returns without error MUST be accepted by `Open`; `ParseAndOpen` composes them and must not skip resolution checks (net.go:124-131).
7. **Identity data integrity.** `Certificate()`/`CertificateChain()` MUST return parsed X.509 that round-trips the store's DER exactly; chain building failures should degrade to leaf-only rather than returning a wrong chain. `Delete()` must remove only the matched identity.
8. **Signing correctness on Windows.** CNG/CAPI signing must map Go `crypto.Hash` values to the correct algorithm identifiers (crypt_strings_windows.go string constants) — a mismatch produces invalid TLS signatures, which must surface as errors, not silent handshake failures.
9. **Errors are diagnosable.** Platform-stub errors ("only supported on linux/darwin") and activation-count errors must reach the user verbatim at startup (integration tests assert on stderr content).

## Edge cases a correct implementation must handle

- `HOST:PORT` with IPv6 literal (`[::1]:8443`), port-only (`:8443`), and missing port (error).
- `unix:` path that already exists on disk (bind error surfaced; `TestOpenUnixSocketListenError`), and abstract/relative paths.
- systemd env with multiple names, same name repeated (IPv4+IPv6 dual sockets → count error), and no `LISTEN_FDS` at all (→ "found none" error).
- Two flags both requesting systemd sockets of different names in one invocation (cache must serve both).
- launchd returning 0 fds, >1 fds, or a non-zero errno.
- Keychain: zero matches (error, no anonymous fallback), multiple matches (latest NotAfter wins), identity matching by serial vs CN ambiguity, cert present without private key (must not be selected as an identity).
- Windows: CURRENT_SERVICE/LOCAL_MACHINE inaccessible (skip silently), duplicate certs across stores (dedupe/latest-NotAfter selection still deterministic).
- CGO_ENABLED=0 builds: cgo files self-exclude; `certstore_other.go` (`!cgo || (!darwin && !windows)`) MUST make `Open` return a clear "not supported" error, and keychain flags must be absent from `--help`.

</details>

---

*Generated by a multi-agent spec → check → verify pipeline (36 agents) run against the working tree at `next`/`e960e41`.*
