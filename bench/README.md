# Ghostunnel benchmarks

External-binary benchmarks for ghostunnel's connection **hot path**. Like the
integration tests, these launch the real ghostunnel binary as a subprocess and
drive it over real sockets — but with purpose-built external load tools instead
of Python, so the measurement reflects ghostunnel and not the driver.

See [`PLAN.md`](PLAN.md) for the full design and rationale.

## What's measured

| Benchmark | Script | Tool | Topology |
|---|---|---|---|
| Handshake rate | `bench-handshake-rate.py` | `openssl s_time`, `vegeta` | tool →(mTLS)→ ghostunnel **server** → HTTP backend |
| Round-trip latency | `bench-roundtrip-latency.py` | `vegeta` | tool →(mTLS, keep-alive)→ ghostunnel **server** → HTTP backend |
| Throughput | `bench-throughput.py` | `iperf3` | iperf3 →(plain)→ ghostunnel **client** →(TLS)→ ghostunnel **server** → iperf3 -s |

## Prerequisites

- **Go** matching `go.mod` (the scripts build a non-coverage `ghostunnel.bench`
  via `go build -trimpath`; override the toolchain with `$GHOSTUNNEL_GO`).
- **Python 3**.
- **openssl** (system) — required by the handshake benchmark and cert generation.
- **vegeta** — handshake (parallel) and latency benchmarks. `brew install vegeta`
  / `go install github.com/tsenart/vegeta/v12@latest`.
- **iperf3** — throughput benchmark. `brew install iperf3` / `apt install iperf3`.

Any benchmark whose tool is missing **skips cleanly** (exit 2 → mage reports
SKIP); it never fails the run.

## Running

```bash
go tool mage bench:all            # everything (skips tools you don't have)
go tool mage bench:handshake      # one workload
go tool mage bench:throughput
go tool mage bench:latency
go tool mage bench:single handshake

# or directly:
python3 bench/bench-handshake-rate.py
```

Tunables (env vars):

| Var | Default | Meaning |
|---|---|---|
| `GHOSTUNNEL_BENCH_DURATION` | `10` | seconds per measured pass |
| `GHOSTUNNEL_BENCH_RUNS` | `3` | measured passes (median reported) |
| `GHOSTUNNEL_BENCH_WARMUP` | `2` | seconds for the discarded warmup pass |
| `GHOSTUNNEL_GO` | `go` | Go toolchain to build with |

## Results

Each run writes `bench/results/<UTC-timestamp>/<bench>.json` and appends a row to
`bench/results/<bench>.csv`. Every record carries `git_sha`, `go_version`,
`host`, `os`, and the parameter axes, so rows stay comparable across commits.
`bench/results/` is gitignored.

## Reading the numbers — caveats that matter

These are documented at length in [`PLAN.md`](PLAN.md#risks--things-that-can-invalidate-results);
the short version:

- **Single-host contention.** Driver, ghostunnel, and backend share CPU. Every
  benchmark cross-checks ghostunnel's own `/_status` metrics (`accept.success`,
  `conn.handshake.count`) to confirm ghostunnel is the bottleneck, not the
  driver. On Linux you can `taskset` to pin CPUs; macOS has no equivalent.
- **Resumption masking (handshake).** `vegeta -keepalive=false` closes TCP per
  request, but Go's TLS client caches session tickets and may *resume* — not a
  full handshake. The handshake benchmark flags this (`resumption_masking`) by
  comparing ghostunnel's handshake count to the request count; treat
  `openssl s_time -new` as the authoritative full-handshake number.
- **vegeta is open-model.** You set a *rate*, not a fixed concurrency
  (`-max-workers` only caps in-flight connections). Latency percentiles are
  reported *at a stated rate*; sweep the rate to find the knee. If `success`
  drops below ~1.0 the offered rate exceeded capacity (`overload` flag) and the
  percentiles are coordinated-omission lower bounds.
- **Baseline is a floor, not a TLS delta** for handshake/latency (no TLS at
  all). Only the iperf3 throughput baseline is a like-for-like overhead delta.
- **No 32 KiB payload cliff.** The proxy's pooled copy buffer is a chunk size,
  not a payload boundary (TLS records cap at 16 KiB). Throughput should rise then
  plateau with size.

## Profiling

Add `--enable-pprof` to a ghostunnel instance (it requires `--status`, already
set by the topology builders) and pull `/debug/pprof/profile` from its status
port mid-run for a CPU flame graph when chasing a regression.
