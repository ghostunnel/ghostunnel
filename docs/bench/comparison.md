# Connection hot-path performance: before vs. after

Benchmark comparison of the performance commits on this branch against the
benchmark baseline.

## Methodology

- **Before** = commit `0bf0b646` ("Add benchmarks for the connection-acceptance
  hot path") — benchmarks present, none of the performance changes applied.
- **After** = `HEAD` (`1d66caf8`) — all three performance commits applied.
- Both runs executed back-to-back on the same machine (Apple M1, `go1.26.4
  darwin/arm64`), `-count=10 -cpu=1,4,8`, compared with `benchstat`.
- Raw data: [`before.txt`](before.txt), [`after.txt`](after.txt),
  [`metrics.txt`](metrics.txt).

The branch has three performance commits, each landing on a different hot path:

| commit | change | where it shows up |
|---|---|---|
| `e9bd5121` | Cache config so we don't re-clone on every connection | `GetServerConfig` / `GetClientConfig` |
| `a74a7191` | Skip metric collection when no sink is configured | `ConnMetricsBookkeeping` (live vs. no-sink) |
| `d5801b00` | Honor container CPU quota for GOMAXPROCS | startup only (not micro-benchmark visible) |

## 1. Config caching (`e9bd5121`) — the headline win

Eliminates the per-connection / per-dial `tls.Config` clone in `certloader`.

| benchmark | before | after | change |
|---|---|---|---|
| GetServerConfig/serial | 128.6 ns | 2.31 ns | **−98.2%** |
| GetServerConfig/parallel-8 | 159.4 ns | 0.55 ns | **−99.7%** |
| GetClientConfig/serial | 136.5 ns | 2.25 ns | **−98.4%** |
| GetClientConfig/parallel-8 | 159.6 ns | 0.51 ns | **−99.7%** |
| **allocations** | **504 B/op, 2 allocs/op** | **0 B/op, 0 allocs/op** | **−100%** |

Geomean across all 12 cases: **−98.8% time**, with allocations eliminated
entirely. The improvement grows under parallelism (60×–290×) because the old
clone allocated on every call; the new path is an allocation-free atomic-pointer
load.

## 2. Skip metrics when no sink configured (`a74a7191`) — default-config win

Not visible in `ConnectionChurn` (both before/after use *live* metrics there,
and the ~1 ms ECDSA handshake dwarfs the bookkeeping). Isolated by the
after-only `ConnMetricsBookkeeping`, which compares the live metric path against
the no-sink path Ghostunnel takes by default (no `--status`,
`--metrics-graphite`, or `--metrics-url`):

| | live (sink set) | nosink (default) | change |
|---|---|---|---|
| -cpu=1 | 386.3 ns | 7.50 ns | **−98.1%** |
| -cpu=4 | 503.2 ns | 2.00 ns | **−99.6%** |
| -cpu=8 | 579.6 ns | 1.46 ns | **−99.8%** |

The key effect is contention: the live path gets *slower* under load
(386 → 580 ns) from mutex contention on the two shared go-metrics timers, while
the no-sink path gets *faster* (7.5 → 1.5 ns). The win compounds under
concurrent connection load in the default configuration.

## 3. GOMAXPROCS / CPU quota (`d5801b00`)

A startup-time runtime tuning change — not observable in micro-benchmarks, and
correctly shows no movement.

## Unchanged paths (expected)

- **ProxyProtoHeader**: flat (within noise), identical allocations — not a
  target of these changes.
- **ConnectionChurn** (end-to-end real TCP + TLS): flat (geomean +1.8%, all
  p > 0.3, ±20–34% noise). Dominated by the handshake, so it cannot surface the
  sub-microsecond bookkeeping/clone savings — that is why the targeted
  micro-benchmarks above exist.

## Bottom line

The two changes that touch the per-connection hot path each remove ~98–99.7% of
their respective cost, and together eliminate **all per-connection heap
allocation** in config setup. The benefit scales up with concurrency — exactly
where a TLS proxy is under pressure.
