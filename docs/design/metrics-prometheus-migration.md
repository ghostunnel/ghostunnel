# Implementation plan: migrate metrics to `prometheus/client_golang`

Status: proposed
Scope: replace the `rcrowley/go-metrics` stack with `prometheus/client_golang`
as the single metrics backend, preserving Ghostunnel's external metric contract
except for a set of explicitly deprecated derived fields.

## 1. Motivation

`rcrowley/go-metrics` is deprecated. It is also the hub of a four-library stack,
all unmaintained, all vendored:

| Dependency | Role | Last release |
|---|---|---|
| `github.com/rcrowley/go-metrics` | instrument types + `DefaultRegistry` | deprecated |
| `github.com/cyberdelia/go-metrics-graphite` | `--metrics-graphite` push | 2016 |
| `github.com/square/go-sq-metrics` | `/_metrics`, `/_metrics/json`, `--metrics-url` JSON | 2017 |
| `github.com/deathowl/go-metrics-prometheus` | `/_metrics/prometheus` bridge | 2022 |

Removing `go-metrics` requires replacing all four. The payoff is dropping four
stale dependencies in favour of one actively maintained library
(`prometheus/client_golang`, already a direct dependency) and owning the two
remaining wire-format translations as small, testable, in-repo adapters.

## 2. Decisions (locked)

1. **Single backend.** Prometheus is the only metrics implementation. No
   `--metrics-backend` flag, no go-metrics fallback, no parallel-run period.
2. **Immediate deprecation** of derived statistical/rate fields (see §4). No
   one-release shim; they are removed in the cut-over.
3. **Incidental drops:** graphite `.999-percentile` and `.count_ps` are removed
   as well (same class of field).

## 3. Current state (the contract to preserve)

### 3.1 Instrument inventory

Producers write to `go-metrics`'s `DefaultRegistry`:

- `proxy` package (`proxy/proxy.go`), per-connection hot path:
  - Counters: `conn.open` (Inc/Dec, gauge-like), `conn.timeout`,
    `accept.total`, `accept.success`, `accept.error`, `accept.timeout`.
  - Timers: `conn.handshake`, `conn.lifetime`.
- `square/go-sq-metrics` background collector: runtime gauges
  (`runtime.mem.*`, `runtime.goroutines`, `runtime.cgo-calls`,
  `runtime.mem.gc.*`) and a GC-pause histogram `runtime.mem.gc.duration`.
  No code calls `AddGauge`, so there are no other dynamic gauges.

The `--metrics-prefix` flag (default `ghostunnel`) is prepended to every name.

### 3.2 Export sinks

Four sinks read the one registry (`main.go` ~599-657, ~928-948):

1. **JSON** — `/_metrics/json`, bare `/_metrics` (default), and `--metrics-url`
   HTTP POST. Format owned by `go-sq-metrics`: an array of
   `{timestamp, metric, value, hostname}` objects, dotted names, timers expanded
   to `.count/.min/.max/.mean/.50/.75/.95/.99-percentile`.
2. **Graphite** — `--metrics-graphite`, raw TCP, 1s interval. Dotted names.
3. **Prometheus** — `/_metrics/prometheus` and `/_metrics?format=prometheus`,
   currently produced by the deathowl bridge (a 1s goroutine that mirrors the
   go-metrics registry into `prometheus.DefaultRegisterer`).
4. The `metricsConsumed` gate: when no sink is configured the proxy gets
   `NilMetrics()` and neither background goroutine starts. **This must be
   preserved.**

## 4. Field-level change matrix

Names are preserved everywhere. Counters, gauges, and `conn.open` are
unchanged. Only timer/histogram-derived fields change.

| Field | JSON | Graphite | Prometheus | After migration |
|---|---|---|---|---|
| `count`, `min`, `max`, `mean` | yes | yes | yes (gauges) | **kept** (count+min+max+sum, mean=sum/count) |
| `50/75/95/99-percentile` | yes | yes | (as gauges) | **kept** via Summary objectives |
| `std-dev` / `std_dev` | — | yes | yes | **removed** |
| `variance` | — | — | yes | **removed** |
| `one/five/fifteen-minute`, `mean-rate` (graphite) | — | yes | — | **removed** |
| `rate1/5/15`, `rate_mean` (prometheus) | — | — | yes | **removed** |
| `999-percentile` | — | yes | — | **removed** |
| `count_ps` | — | yes | — | **removed** |
| `_timer_bucket{le=...}` | — | — | yes | **removed** (native Summary instead) |

Net effect by format:

- **JSON: byte-for-byte unchanged.** Today's JSON timers already only emit
  `count/min/max/mean/{50,75,95,99}-percentile`; none of the deprecated fields
  exist in JSON. This is the most-consumed format and takes zero breakage.
- **Graphite:** timers keep `count/min/max/mean/{50,75,95,99}-percentile`; lose
  `std-dev`, `one/five/fifteen-minute`, `mean-rate`, `999-percentile`,
  `count_ps`. The GC histogram likewise loses `std-dev`.
- **Prometheus:** moves from the deathowl all-gauges representation to **native
  Summary** output: `ghostunnel_conn_handshake{quantile="0.5"|...}`,
  `..._sum`, `..._count`, plus the unchanged `go_*`/`process_*` collectors.

> Note: preserved percentile *values* shift slightly — go-metrics uses an
> exp-decay reservoir; `prometheus.Summary` uses a CKMS sliding window. Same
> fields and names, statistically equivalent numbers, not identical. Documented
> as a known change.

## 5. Target architecture

A single new in-repo package, `metrics/`, owns one `*prometheus.Registry` and
exposes Ghostunnel's instrument handles. It has exactly one implementation (no
pluggable backend abstraction). Its purpose is encapsulation: keep
`prometheus` out of `proxy/`, and give both legacy adapters one source to read.

```
proxy/, main.go ─► metrics/ (prometheus-backed) ─► *prometheus.Registry (Gatherer)
                                                       ├─ jsonexport  (Gather→DTO→sq JSON)   : /_metrics/json, /_metrics, --metrics-url
                                                       ├─ graphite    (Gather→DTO→dotted)    : --metrics-graphite
                                                       └─ promhttp.HandlerFor(reg)           : /_metrics/prometheus  (native)
```

### 5.1 Package layout

```
metrics/
  metrics.go        // Registry wrapper, Metrics struct, Live/Nil constructors, instrument handles
  timer.go          // internal Timer: count+sum+min+max + prometheus.Summary
  jsonexport.go     // Gatherer → sq-compatible JSON ([]map / ServeHTTP / POST body)
  graphite.go       // Gatherer → graphite line protocol + push loop
  runtime.go        // runtime/GC gauge collector (replaces sq-metrics collectMetrics)
  *_test.go         // unit tests per adapter, golden tests
```

### 5.2 Instrument handles (replaces `proxy.Metrics`)

`proxy` keeps its `Metrics` struct shape but the field types become small
interfaces owned by the `metrics` package, so the hot-path call sites
(`Inc(1)`, `Dec(1)`, `UpdateSince(start)`) are unchanged:

```go
package metrics

type Counter interface { Inc(int64); Dec(int64) } // Dec only meaningful for conn.open
type Timer   interface { UpdateSince(time.Time) }

type Metrics struct {
    OpenCounter, ConnTimeoutCounter, TotalCounter,
    SuccessCounter, ErrorCounter, HandshakeTimeoutCounter Counter
    HandshakeTimer, ConnTimer Timer
}

func LiveMetrics(r *Registry) *Metrics // registers canonical names on r
func NilMetrics() *Metrics             // all no-op handles (preserves no-sink fast path)
```

- Counters back onto `prometheus.Counter`; `conn.open` backs onto a
  `prometheus.Gauge` (Inc/Dec) — its JSON/graphite single-value output is
  identical to today's counter value.
- `NilMetrics()` returns no-op handles; the `metricsConsumed` gate in `main.go`
  is preserved verbatim.

### 5.3 Internal Timer (the only non-trivial instrument)

```go
type timer struct {
    summary prometheus.Summary // {0.5,0.75,0.95,0.99} objectives → quantiles, _sum, _count
    count   atomic.Int64
    sumNs   atomic.Int64
    minNs   atomic.Int64       // maintained via CAS
    maxNs   atomic.Int64       // maintained via CAS
}
func (t *timer) UpdateSince(start time.Time) {
    d := time.Since(start)
    t.summary.Observe(d.Seconds())
    // update count/sum/min/max atomically for the JSON/graphite adapters
}
```

`count/sum/min/max` feed JSON and graphite (`mean = sum/count`); the Summary
feeds quantiles and the native Prometheus endpoint. No EWMA, no variance — the
deprecation in §4 is what makes this simple.

### 5.4 Adapters

Both legacy adapters call `registry.Gather()` → `[]*dto.MetricFamily` and format
the result. No third-party bridge code.

- **jsonexport.go** reproduces `go-sq-metrics`'s `SerializeMetrics` output:
  walk the gathered families, emit
  `{timestamp, metric: "<prefix>.<dotted-name>[.<field>]", value, hostname}`.
  Summary families expand to `.count/.50/.75/.95/.99-percentile`; the timer's
  `.min/.max/.mean` come from the count/sum/min/max fields exposed as helper
  metrics or read from the `metrics` package directly. Provides `ServeHTTP` and
  a `postLoop(url, interval)` matching `--metrics-url`.
- **graphite.go** reproduces the kept subset of cyberdelia's line output and a
  `pushLoop(addr, interval)` over raw TCP.

`/_metrics/prometheus` becomes `promhttp.HandlerFor(reg, promhttp.HandlerOpts{})`
— the deathowl bridge and its 1s `UpdatePrometheusMetrics` goroutine are deleted.
`client_golang`'s default Go/process collectors are registered on `reg` so
`go_*`/`process_*` remain.

### 5.5 Name mapping

- Prometheus names: dots/dashes → underscores, prefix as namespace
  (`ghostunnel_conn_open`), matching today's deathowl `flattenKey` output.
- JSON/graphite names: dotted, prefix-prepended, exactly as today.
- One mapping table in `metrics/` is the single source of truth for both the
  registered Prometheus name and the legacy dotted name per metric.

## 6. Work breakdown

### Phase 0 — Freeze the oracle (no production code change)

Capture today's output of all four sinks as golden fixtures and add tests that
assert against them:

- JSON: start a server with `--status`, GET `/_metrics/json`; normalize the
  volatile `timestamp`/`hostname` fields; store golden. Assert **byte-stable**
  across the cut-over.
- Graphite: point `--metrics-graphite` at a throwaway `net.Listener`, capture
  one flush; store golden (regenerated to the post-deprecation field set in
  Phase 1, with the diff reviewed explicitly).
- `--metrics-url`: point at an `httptest.Server`, capture one POST body; golden.
- Prometheus: GET `/_metrics/prometheus`; golden (regenerated in Phase 1).

Also extend `tests/test-server-status-port.py` to assert specific metric names
(`conn.open`, `accept.total`, `conn.handshake.99-percentile`) rather than just
"parses as JSON".

### Phase 1 — Cut over (one change, reviewable as ordered commits)

1. Add `metrics/` package: Registry wrapper, `Metrics`/`Live`/`Nil`, internal
   timer, name mapping. Unit tests.
2. Add `jsonexport.go` + `graphite.go` adapters with unit tests driven off a
   hand-built registry (assert exact field sets).
3. Add `runtime.go` GC/runtime gauge collector (replaces sq-metrics
   `collectMetrics`).
4. Rewrite `proxy/proxy.go` to use `metrics.Metrics` (hot-path call sites
   unchanged); update `proxy` tests/benchmarks (`LiveMetrics`/`NilMetrics`
   signatures).
5. Rewire `main.go`: build the registry, wire the three sinks and the
   `metricsConsumed` gate to the new package; swap `/_metrics/prometheus` to
   native `promhttp`; delete the deathowl bridge goroutine.
6. Remove dependencies: drop the four libraries from `go.mod`, `go mod tidy`,
   re-vendor (`go mod vendor`), verify `vendor/modules.txt`.
7. Docs + release notes: update `docs/networking/metrics.md` (Graphite +
   Prometheus field tables, deprecation/migration note), regenerate man pages,
   add a breaking-change release-note entry.
8. Validate: `go tool mage test:all` and `go tool mage test:docker`; rerun
   `BenchmarkConnMetricsBookkeeping` (`-cpu=1,4,8`) against the baseline in
   `docs/bench/` to confirm no per-connection regression.

## 7. Testing strategy

- **Golden contract tests** (Phase 0) gate the cut-over; JSON golden asserted
  byte-stable, graphite/prometheus goldens diffed and re-approved.
- **Adapter unit tests:** build a registry with known observations, assert the
  exact emitted line/JSON field set (positive: kept fields present; negative:
  deprecated fields absent).
- **Integration:** existing Python status-port test (extended) + new
  graphite-push test (TCP listener) + new metrics-url test (`httptest`).
- **Benchmarks:** reuse `proxy.BenchmarkConnMetricsBookkeeping` and
  `BenchmarkConnectionChurn` to confirm the hot path is not slower.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Percentile values shift (reservoir → CKMS) | Same fields/names; documented in metrics.md + release notes |
| Deprecated fields removed | Intended; called out prominently in release notes and metrics.md migration table |
| Prometheus output shape change (gauges → native Summary) | Names preserved; update scrape docs; breaking-change note |
| No parallel-run safety net | Phase 0 goldens are the regression oracle |
| `vendor/` drift after dep removal | `go mod tidy` + `go mod vendor` + CI `go mod verify` |
| Summary is mutex-guarded → enabled-path contention unchanged | Out of scope; see §9 |

## 9. Out of scope / follow-up

This migration optimizes for compatibility and maintainability, not throughput.
`prometheus.Summary` is mutex-guarded, so it does **not** resolve the
enabled-metrics timer contention measured in `docs/bench/`. A separate,
optional follow-up could add a `--metrics-timer-type=summary|histogram` choice:
`prometheus.Histogram` is lock-free and would close the contention gap, at the
cost of bucketed (approximate) percentiles instead of exact quantiles.

## 10. Release impact

Single breaking release for Graphite and Prometheus consumers; JSON and
`--metrics-url` consumers are unaffected. Requires a prominent release-note
entry and a migration table in `docs/networking/metrics.md`. Given current 1.x
versioning, ship either as a clearly-flagged minor or fold into the next major.
