# Ghostunnel external-binary benchmark — plan

Status: implemented (see bench/README.md for usage)
Branch: `cs/benchmarks`

## Goal

Benchmark the **real ghostunnel binary as a subprocess** — same philosophy as the
Python integration tests (launch it, drive it over real sockets, tear it down) —
targeting the connection **hot path** in `proxy/proxy.go`:

1. **Connection churn / handshake rate** — `Accept()` (`proxy.go:315`) → semaphore
   acquire → `forceHandshake()` (`proxy.go:436`, TLS + client-cert verify) →
   backend dial → teardown. Short-lived connections, dominated by the mTLS
   handshake.
2. **Steady-state throughput** — `fuse()` (`proxy.go:455`) → `copyData()`
   (`proxy.go:486`) → `io.CopyBuffer` (`proxy.go:533`) over the 32 KiB pooled
   buffer (allocated `proxy.go:267` as `1<<15`; fetched/returned `proxy.go:510-511`),
   TLS record crypto dominated.
3. **Many concurrent connections** — request/response ping-pong across a large
   fan-out, stressing the per-connection goroutine model, scheduler, and the
   `--max-concurrent-conns` semaphore (`proxy.go:324`).

## Approach: external load tools + thin Python orchestrator

External tools sit in the **data path** (they generate load). A thin **Python
orchestrator** reuses the *patterns* of `tests/common.py` — cert generation
(`RootCert`), subprocess launch + readiness polling, graceful teardown — to set
everything up, invoke the tool, parse its output, and tear down. Python is never
in the hot path, so its overhead does not taint results.

> Note: we reuse `tests/common.py` *patterns and the `RootCert` recipe*, not its
> module-global port/state. `tests/common.py` allocates exactly three ports
> (`STATUS_PORT`, `LISTEN_PORT`, `TARGET_PORT`) at **import time** as
> process-global singletons (`common.py:88-90`), and `status_info()` hardcodes
> the global `STATUS_PORT` (`common.py:194-210`). The benchmark needs to run
> **multiple ghostunnel instances in one process** (the throughput full-chain
> topology runs a client *and* a server) and to scrape a *specific* instance's
> status port, so `bench_common.py` allocates a fresh port per endpoint via
> `get_free_port()` and builds status URLs explicitly rather than calling
> `status_info()`/`start_ghostunnel_server()` as-is.

### Tool selection

| Workload | Tool | Why |
|---|---|---|
| Steady-state throughput | `iperf3` | Plain TCP, transparent; measures Gbit/s through the tunnel |
| Connection churn / handshake rate | `openssl s_time` (serial) + `vegeta -keepalive=false` (parallel) | Force a fresh handshake per request; present a client cert |
| Concurrent round-trip latency | `vegeta -keepalive=true` | p50/p95/p99 at a fixed request *rate*, with client-cert support |

`vegeta` is an **HTTP** load tool, so any topology it drives must terminate at an
**HTTP backend**. It supports mTLS via `-cert`/`-key` (PEM client cert/key) and
`-root-certs` (CA bundle), and `-keepalive=false` closes the TCP connection per
request. `openssl s_time` supports `-cert`/`-key`/`-cafile` for mTLS, `-new`
vs `-reuse` (full vs resumed handshake), `-www /` to actually fetch a page, and
`-tls1_2`/`-tls1_3` to pin the version. All emit machine-parseable output
(`iperf3 -J`, `vegeta report -type=json`; `s_time` prints
`<N> connections in <T> real seconds` which we parse to conns/sec).

**Important caveats baked into tool choice (see Risks):**

- `vegeta` is an **open-model, rate-driven** tool: you set `-rate` (req/s) and it
  bounds in-flight connections with `-max-workers`. It is *not* a fixed-concurrency
  closed-loop generator. We report latency percentiles **at a stated rate**, and
  use `-max-workers` to cap connection count for the concurrency axis.
- `openssl s_time` is **single-threaded** (one connection at a time): it measures
  the *serial, round-trip-bound* handshake rate, i.e. handshake latency⁻¹, not
  peak parallel handshakes/sec. It is the authoritative **full-handshake** signal
  (`-new`) and the resumption signal (`-reuse`); `vegeta -keepalive=false` is the
  parallel/peak signal but can silently *resume* (see Risks).

### Topologies

- **Handshake + latency** (core mTLS hot path) — server mode:
  `vegeta`/`s_time` *(plain HTTP request over TLS, presenting a client cert)* →
  ghostunnel **server** *(TLS termination, mTLS via `--allow-ou`)* → tiny **HTTP**
  backend *(plain HTTP)*. The load tool speaks HTTPS+mTLS to ghostunnel;
  ghostunnel verifies the client cert, strips TLS, and forwards plain HTTP to the
  backend.
- **Throughput** — full chain, so both iperf3 ends are plain TCP:
  `iperf3 -c` *(plain TCP)* → ghostunnel **client** *(adds TLS)* → ghostunnel
  **server** *(mTLS, strips TLS)* → `iperf3 -s` *(plain TCP)*. This is also the
  canonical real deployment. iperf3's control + data streams ride the single
  proxied port transparently; `-P` parallel streams open additional connections
  through the tunnel.
- **Baseline (floor, not a delta)** — tool → backend directly, **no ghostunnel,
  no TLS**. This is the driver+backend+loopback floor, used to confirm we are not
  backend/driver-bound. It is *not* an mTLS-vs-mTLS comparison; do not report
  "ghostunnel overhead" as `tunnel − baseline` for the handshake/latency cases,
  because baseline has no TLS at all. For throughput, `iperf3` direct ↔ through
  the tunnel is a meaningful overhead delta (both move the same plaintext bytes).

### Backends

- Trivial fast **HTTP backend** (`http_backend.py`) with a fixed-size response
  (small for handshake/latency, large for HTTP-body throughput) — kept
  lightweight so it is never the bottleneck. Used by the vegeta/s_time topologies.
- `iperf3 -s` for bulk throughput.

### Binary build

A **release-style binary** via plain `go build` (NOT `-cover -tags coverage` —
coverage instrumentation distorts timing). Separate artifact from
`ghostunnel.cover` (call it `ghostunnel.bench`); add `-trimpath`. Build it with
the toolchain matching `go.mod`'s `go` directive (fail loudly on mismatch, as the
project already does), and rebuild as a mage dependency on every `bench:*` run so
the binary never drifts from the source tree (mirrors how `Test.build` gates the
integration suite, `magefile.go:479`).

### Parameter matrix

- **Cert/key algorithm**: RSA-2048 vs ECDSA P-256 vs Ed25519 (large effect on
  handshake rate) — generated via the `RootCert` recipe (`common.py:237-243`
  already has all three keygens). Skip Ed25519 if OpenSSL lacks support
  (`check_ed25519_support` pattern).
- **TLS version**: 1.2 vs 1.3. Ghostunnel only exposes `--max-tls-version`
  (`main.go:134`, **hidden**, accepts `TLS1.2`/`TLS1.3`, max-only — there is no
  min-version flag). Pin 1.2 with `--max-tls-version=TLS1.2`; leave unset for the
  Go default (1.3). The load tool must pin to match (`s_time -tls1_2`/`-tls1_3`;
  vegeta has no version flag, so 1.2 is exercised only via the ghostunnel cap).
- **Session resumption**: full vs resumed (`s_time -new` vs `-reuse`) — resumption
  is intentional in ghostunnel, so report both axes explicitly.
- **Payload size** (throughput / HTTP body): sweep e.g. 1 KiB / 16 KiB / 64 KiB /
  1 MiB. Note: the 32 KiB pool buffer is the *copy chunk size*, not a payload
  cliff (the TLS record max is 16 KiB), so do **not** expect a throughput
  discontinuity at 32 KiB — see Risks.
- **`--max-concurrent-conns`** (`main.go:142`): unlimited (`0`) vs bounded
  (semaphore effect).
- **PROXY protocol**: deferred — reframes the wire to the backend, needs a
  PROXY-aware backend; later axis.

### Repo structure

```
bench/
  PLAN.md                  # this document
  bench_common.py          # shared helpers + topology builders (see Phase 0 contract)
  http_backend.py          # tiny fixed-response HTTP backend
  bench-handshake-rate.py
  bench-roundtrip-latency.py
  bench-throughput.py
  results/                 # timestamped result dirs (gitignored)
  README.md                # tool install, how to run, caveats
```

Each script preflight-checks its tool is installed (skip-with-reason via
`sys.exit(2)`, like `require_pebble`, so the mage runner reports `SKIP` —
`magefile.go:590`), builds the topology through `bench_common.py`, runs a
discarded warmup pass + N measured passes, and writes a normalized result.

### Result storage

Results land in `bench/results/<UTC-timestamp>/<bench-name>.json` plus an appended
row in `bench/results/<bench-name>.csv` for over-time tracking, and a one-line
human summary to stdout. Each JSON record carries a fixed schema so runs are
diffable:

```
{ "bench": "...", "git_sha": "...", "go_version": "...", "host": "...",
  "os": "...", "params": {algorithm, tls_version, resumption, payload, conns, ...},
  "metric": {primary, unit, p50, p95, p99, stddev, runs}, "raw": {...} }
```

Capturing `git_sha`/`go_version`/`host` is what makes a CSV row meaningful later.
CI regression gating (benchstat-style) is out of scope for v1.

### Mage targets

`bench:all`, `bench:handshake`, `bench:latency`, `bench:throughput`,
`bench:single <name>` — each depends on a release-binary build target, then
invokes the Python orchestrators. Iterations/warmup/duration via env vars
(`GHOSTUNNEL_BENCH_DURATION`, `GHOSTUNNEL_BENCH_RUNS`), mirroring the
`GHOSTUNNEL_TEST_PARALLEL` convention.

### Measurement rigor (documented in README)

- Warmup pass discarded; fixed-duration measured passes; multiple runs → report
  median + spread.
- Single-host CPU contention (driver + ghostunnel + backend on one box) is real —
  document it, optionally pin CPUs (`taskset` — **Linux only**; macOS has no
  equivalent, note this), and **cross-check against ghostunnel's `/_status`
  metrics** (`conn.handshake` timer, `accept.*` counters — confirmed present,
  `proxy.go:51-58`, `common.py:376-398`) to confirm ghostunnel is the bottleneck,
  not the driver.
- Optional `--enable-pprof` (`main.go:152`, requires `--status`) → pull
  `/debug/pprof/profile` mid-run for flame graphs when investigating a regression.

### Reused vs. new

- **Reuse**: subprocess+readiness pattern, `RootCert` cert recipe, `get_free_port`,
  the `/_status` polling idiom, mage build plumbing; keep
  `proxy/benchmark_test.go` (`BenchmarkCopyData`) as a complementary in-process
  `copyData` micro-bench.
- **New**: `bench/` orchestrators + shared helpers + topology builders, HTTP
  backend, release-build + `bench:*` mage targets, README/docs.

---

## Implementation via multiple agents

The work decomposes into one shared foundation that everything depends on, three
benchmark scripts buildable in parallel against that foundation's API, then an
integration + an adversarial-verification pass. Run it as a 4-phase pipeline.

### Dependency graph

```
Phase 0  ─────────────►  Phase 1 (fan-out ×3)  ─────►  Phase 2  ─────►  Phase 3
foundation + contract     handshake | throughput        integrate       verify
(barrier)                 | latency  (parallel)          (mage+docs)     (run it)
```

The Phase 0 → Phase 1 edge is a **hard barrier**: the three benchmark agents all
import `bench_common.py`, so its API must be frozen first. Within Phase 1 the
three agents own disjoint files and run concurrently.

> **Hidden-conflict fix:** the original split gave Phase 0 only low-level
> primitives and let each Phase-1 agent wire up its own topology. But the
> handshake and latency scripts need the *same* (server → HTTP backend) topology,
> and all three need consistent port allocation and status scraping. Three agents
> hand-rolling topology independently guarantees drift that Phase 2 then has to
> reconcile. So **Phase 0 owns the topology builders**, and Phase-1 agents only
> write load-driving + sweep + result-emit logic against them. This shrinks the
> Phase-2 "reconcile drift" step to near-zero.

### Phase 0 — Foundation (1 agent, blocking)

Owns and freezes the shared contract. Deliverables:

- `bench/bench_common.py`:
  - `build_release_binary() -> str` — path to a plain (`-trimpath`, no-coverage)
    `go build` binary, toolchain pinned to `go.mod`.
  - `gen_certs(algorithm) -> CertSet` — `RootCert` wrapper returning paths for
    CA, server cert/key, client cert/key (PEM; vegeta and s_time need separate
    `-cert`/`-key` PEM files, not a `.p12`).
  - **Topology builders** (own the multi-instance port allocation):
    - `start_server_topology(certs, *, tls_max=None, max_conns=0, resp_size=...)
      -> Topology` — launches the HTTP backend + one ghostunnel **server**
      (`--listen`, `--target`, `--cacert`, `--allow-ou=client`, `--status`),
      returns listen addr, status addr, and a teardown handle.
    - `start_fullchain_topology(certs, *, tls_max=None) -> Topology` — launches
      `iperf3 -s` + ghostunnel **server** + ghostunnel **client**, wiring
      client.listen → client.target=server.listen → server.target=iperf3, each
      with its own `--status`. Returns the client-listen addr (where iperf3 -c
      connects) + both status addrs.
  - `wait_ready(status_addr)` — poll `https://<status_addr>/_status` (TLS, no
    verify — status defaults to HTTPS on TCP, `main.go:275-292`) until accepting.
  - `require_tool(name)` — preflight; `sys.exit(2)` skip-with-reason if missing.
  - `scrape_status(status_addr) -> dict` — fetch `/_status`, return the
    `conn.handshake`/`accept.*` metrics for cross-checking (does **not** use
    `common.py:status_info`, which is bound to the global port).
  - `Result` + `write_result(result)` — normalized JSON+CSV emitter (schema
    above) + human summary; owns `bench/results/` layout.
- `bench/http_backend.py` — tiny fixed-response HTTP backend (size configurable).
- Release-build mage helper (the non-coverage `go build`).

**Exit criterion / contract handed to Phase 1:** the exact signatures above,
written as a docstring block at the top of `bench_common.py`. The three Phase-1
agents get this contract verbatim and code against it without reading each
other's files.

### Phase 1 — Benchmark scripts (3 agents, parallel)

Each agent owns exactly one file, imports only `bench_common.py`, must not touch
`magefile.go`, `http_backend.py`, or each other's files.

- **Agent A — handshake rate** → `bench/bench-handshake-rate.py`
  Uses `start_server_topology`. `openssl s_time -new`/`-reuse` (serial, the
  authoritative full-vs-resumed signal) **and** `vegeta -keepalive=false`
  (parallel peak). Sweep cert algorithm (RSA/ECDSA/Ed25519) and resumption.
  Must report s_time and vegeta numbers separately and flag if they diverge
  (resumption masking — see Risks).
- **Agent B — throughput** → `bench/bench-throughput.py`
  Uses `start_fullchain_topology`. `iperf3 -c -J` + payload/parallel-stream sweep;
  report Gbit/s and overhead vs. the iperf3-direct baseline.
- **Agent C — round-trip latency** → `bench/bench-roundtrip-latency.py`
  Uses `start_server_topology`. `vegeta -keepalive=true` at a fixed `-rate`,
  swept across rates and `-max-workers` (connection cap); report p50/p95/p99.
  State that vegeta is rate-driven (open model), not fixed-concurrency.

Each prompt includes: the frozen `bench_common.py` contract, the target topology,
the exact tool invocation (flags below), and the parameter sub-matrix it owns.

Exact invocations (for the agent prompts):

```
# handshake, full vs resumed (serial), per algorithm:
openssl s_time -connect <server_listen> -cert client.crt -key client.key \
  -cafile root.crt -www / -new   -time <D>      # full handshakes/sec
openssl s_time -connect <server_listen> -cert client.crt -key client.key \
  -cafile root.crt -www / -reuse -time <D>      # resumed/sec

# handshake/latency parallel via vegeta (HTTP backend behind ghostunnel server):
echo "GET https://<server_listen>/" | \
  vegeta attack -cert client.crt -key client.key -root-certs root.crt \
    -keepalive=false -rate <R> -duration <D>s -max-workers <W> | \
  vegeta report -type=json

# throughput full chain (iperf3 plain TCP both ends, TLS in the middle):
iperf3 -c <client_listen_host> -p <client_listen_port> -t <D> -P <streams> -J
# baseline: iperf3 -c directly against iperf3 -s, no tunnel.
```

### Phase 2 — Integration (1 agent, after Phase 1 barrier)

Single owner of the shared, conflict-prone surface:

- Add `bench:*` mage targets (`all`, `handshake`, `latency`, `throughput`,
  `single`) wiring the release build to each script; add `bench/results/` to
  `.gitignore`.
- Write `bench/README.md` (tool install — `iperf3`, `vegeta`; system `openssl` —
  usage, measurement-rigor caveats, the Risks section).
- Reconcile any residual drift in the result schema across the three scripts.

This is a barrier because all three scripts converge on `magefile.go` and the
README; one owner avoids three agents racing the same files.

### Phase 3 — Adversarial verification (1+ agents)

Don't trust the scripts because they run — trust them because the numbers are
sane.

- Execute `bench:all` end-to-end on this host (skip cleanly if external tools are
  absent — note: neither `vegeta` nor `iperf3` is currently installed here).
- Sanity checks that should hold:
  - baseline (no ghostunnel) is faster / lower-latency than through-tunnel;
  - handshake rate RSA-2048 ≪ ECDSA P-256 ≈ Ed25519 (RSA server-side signing is
    the expensive operation);
  - `-reuse` handshake rate ≫ `-new` (resumption working);
  - throughput rises with payload size and plateaus (do **not** assert a 32 KiB
    cliff — the buffer is a copy-chunk size, not a payload boundary).
- **Cross-check** tool-reported numbers against `/_status`
  (`conn.handshake.count`, `accept.success`/`accept.total`) to confirm ghostunnel
  — not the driver or backend — is the bottleneck.
- Report any benchmark that silently measures the wrong thing — especially
  vegeta `-keepalive=false` whose `conn.handshake` count should equal its request
  count; if it's lower, sessions are being resumed and it's not measuring full
  handshakes (cross-check against the s_time `-new` number).

### How to launch it

Maps onto a `Workflow` pipeline with a barrier after foundation:

```js
phase('Foundation')
const contract = await agent('Build bench/bench_common.py (helpers + topology builders) + http_backend.py + release-build mage helper; return the frozen helper API as a docstring contract', { schema: CONTRACT })

phase('Scripts')               // fan-out, all three get `contract` in their prompt
const scripts = await parallel([
  () => agent(`Write bench/bench-handshake-rate.py against this contract:\n${contract.api}`),
  () => agent(`Write bench/bench-throughput.py against this contract:\n${contract.api}`),
  () => agent(`Write bench/bench-roundtrip-latency.py against this contract:\n${contract.api}`),
])

phase('Integrate')             // single owner of magefile.go + README + .gitignore
await agent('Add bench:* mage targets, write bench/README.md, gitignore results/; reconcile result schema')

phase('Verify')                // adversarial: run it, sanity-check numbers vs /_status
await agent('Run bench:all; verify baseline<tunnel, RSA<ECDSA handshake rate, reuse>new, handshake count == request count for keepalive=false; cross-check /_status; report anything measuring the wrong thing')
```

If run manually: do Phase 0 yourself (or one agent), then spawn the three Phase-1
agents in a single message so they run concurrently, then Phase 2, then Phase 3.

### Suggested build order (serial fallback)

1. Phase 0 — `bench_common.py` (helpers + topology builders) + release-build
   target + HTTP backend + preflight.
2. Handshake-rate script (headline metric).
3. Throughput script.
4. Round-trip latency script.
5. README + result-schema normalization + `.gitignore`.
6. Verification run.

## Risks / things that can invalidate results

- **Resumption masking full handshakes.** `vegeta -keepalive=false` closes the TCP
  connection per request but Go's TLS client caches session tickets, so the *next*
  connection may resume — it will *not* perform a full handshake, silently
  inflating the "handshake rate." This is the same class of trap as the ACME-test
  resumption gotcha. Mitigation: treat `openssl s_time -new` as the authoritative
  full-handshake number, and in Phase 3 assert vegeta's `conn.handshake.count`
  equals its request count.
- **Measuring the driver/backend/loopback, not ghostunnel.** On a single host the
  load tool, ghostunnel, and backend share CPU. Always cross-check `/_status`
  (`accept.success`, `conn.handshake`) and confirm the backend baseline is well
  above the through-tunnel number. `s_time` being single-threaded means it can be
  *driver-latency*-bound rather than ghostunnel-bound — it measures serial
  handshake latency, full stop.
- **vegeta is open-model.** It generates a *rate*, not a fixed concurrency. If the
  rate exceeds what ghostunnel can serve, `-max-workers` saturates and latency
  blows up (coordinated omission territory). Report the rate alongside every
  percentile; sweep rate to find the knee rather than quoting one number.
- **No 32 KiB payload cliff.** The pooled buffer (`proxy.go:267`) is the copy
  chunk size; TLS records cap at 16 KiB. Throughput should rise then plateau with
  payload — there is no special boundary at 32 KiB. Asserting one would be a false
  expectation.
- **Baseline is a floor, not a TLS delta** for handshake/latency (it has no TLS).
  Only the iperf3 throughput baseline is a like-for-like overhead delta.
- **Port collisions across concurrent runs.** Every endpoint (backends, each
  ghostunnel listen + status, iperf3) must get its own `get_free_port()`; do not
  reuse the `common.py` global `LISTEN_PORT`/`TARGET_PORT`/`STATUS_PORT`
  singletons — they can't represent the multi-instance full-chain topology and
  would collide if two benches run at once.
- **Platform.** `taskset` is Linux-only (no macOS pinning). `iperf3`/`vegeta`
  install differs by OS; gate with skip-if-missing. Status is HTTPS-on-TCP by
  default (`main.go:275-292`), so scrape with TLS + no verification.
- **Binary drift / Go version.** Rebuild the release binary as a mage dep on every
  run and pin the toolchain to `go.mod`, or numbers from different commits become
  incomparable. Record `git_sha` + `go_version` in every result.

## Open questions

- External deps (`iperf3`, `vegeta`; system `openssl`) are opt-in dev tools gated
  by skip-if-missing — confirm acceptable (neither iperf3 nor vegeta is installed
  on the current dev host).
- Is the open-model `vegeta` latency story sufficient, or do we also want a
  closed-loop fixed-concurrency generator (e.g. `bombardier -c <N>`) for the
  "many concurrent connections" axis? `vegeta` alone can't express a fixed
  closed-loop concurrency cleanly.
- CI regression gating (benchstat-style) is **out of scope** for v1; on-demand
  local runs only.
