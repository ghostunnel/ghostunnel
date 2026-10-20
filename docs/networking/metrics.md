---
title: Metrics & Profiling
description: Expose status, health checks, and metrics in JSON or Prometheus format via the built-in status port.
weight: 40
aliases:
  - /docs/metrics/
---

Ghostunnel provides a status port, a TCP port (or UNIX socket) that
exposes status and metrics over HTTP(S). Enable it with `--status`. Profiling
endpoints can be added with `--enable-pprof`.

The X.509 certificate on the status port will be the same as the certificate
used for proxying (either the client or server certificate). This means you can
use the status port to inspect/verify the certificate that is being used, which
can be useful for orchestration systems.

Example invocation with status port enabled:

```bash
ghostunnel client \
    --listen localhost:8080 \
    --target localhost:8443 \
    --keystore test-keys/client-keystore.p12 \
    --cacert test-keys/cacert.pem \
    --status localhost:6060
```

Here the status port is set to `localhost:6060`. Ghostunnel starts an internal
HTTPS server on that address. You can also specify a UNIX socket instead of a
TCP port, in which case the status endpoints are served over plain HTTP (UNIX
socket status listeners never use TLS). On TCP, Ghostunnel also falls back to
plain HTTP if the configured certificate source cannot act as a server (for
example, in client mode with `--disable-authentication`).

How to check status and read connection metrics:

```bash
# Status information (JSON)
curl --cacert test-keys/cacert.pem https://localhost:6060/_status

# Metrics information (JSON)
curl --cacert test-keys/cacert.pem 'https://localhost:6060/_metrics/json'

# Metrics information (Prometheus)
curl --cacert test-keys/cacert.pem 'https://localhost:6060/_metrics/prometheus'
```

The bare `/_metrics` endpoint serves JSON by default and Prometheus output
when called with the `format=prometheus` query parameter (e.g.
`/_metrics?format=prometheus`).

How to use profiling endpoints, if `--enable-pprof` is set:

```bash
# Human-readable goroutine dump
curl --cacert test-keys/cacert.pem 'https://localhost:6060/debug/pprof/goroutine?debug=1'

# Analyze CPU profile using pprof tool
go tool pprof -seconds 5 https+insecure://localhost:6060/debug/pprof/profile
```

Note: `go tool pprof` does not support custom CA certificates, so the example
above uses `https+insecure`. Use the standard `https` scheme if Ghostunnel's
certificate is trusted by your system (see [golang/go#20939][pprof-bug]). For
more on pprof, see the [`runtime/pprof`][pprof] and
[`net/http/pprof`][http-pprof] docs.

[pprof]: https://pkg.go.dev/runtime/pprof
[http-pprof]: https://pkg.go.dev/net/http/pprof
[pprof-bug]: https://github.com/golang/go/issues/20939

## Shutdown Endpoint

*Available since v1.8.1.*

If `--enable-shutdown` is set, a `/_shutdown` endpoint is available on the
status port. Sending an HTTP POST request to this endpoint will trigger a
graceful shutdown of the Ghostunnel process. Any other HTTP method returns 405
Method Not Allowed. For details on what happens after shutdown is triggered,
including signal handling, connection draining, and the `--shutdown-timeout`
flag, see
[Graceful Shutdown]({{< ref "graceful-shutdown.md" >}}).

## Backend Healthchecks

The `/_status` endpoint includes a backend healthcheck. In server mode,
Ghostunnel performs a plain TCP connection check against the `--target`
address by default; in client mode, the check is a full TLS connection to the
target. In server mode you can override the default check with
`--target-status=URL` (must use `http://` or `https://` scheme) to perform an
HTTP GET against the given URL instead. Ghostunnel expects an HTTP 200
response. The `--target-status` flag is only available in server mode.

The `/_status` JSON response includes:

* `backend_ok`: boolean indicating if the backend check passed
* `backend_status`: string of `ok` or `critical`
* `backend_error`: string of error message if the check failed

If the backend check fails, the `/_status` endpoint returns HTTP 503.

## Metric Names

Ghostunnel exports the following base metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `conn.open` | Gauge | Number of currently open connections |
| `conn.timeout` | Counter | Connections closed by a timeout during data transfer{{% since "v1.12.0" %}}: idle (`--idle-timeout`), maximum lifetime (`--max-conn-lifetime`), or a half-closed connection that stayed silent for `--close-timeout`{{% /since %}} |
| `accept.total` | Counter | Total connection attempts accepted |
| `accept.success` | Counter | Connections successfully established |
| `accept.error` | Counter | Failed connection attempts |
| `accept.timeout` | Counter | TLS handshake timeouts (server mode only) |
| `conn.handshake` | Timer | TLS handshake duration (server mode only) |
| `conn.lifetime` | Timer | Total connection lifetime |
{{% since "v1.12.0" %}}| `conn.error` | Counter | I/O errors during data transfer (counted per direction, so one connection can add up to two) |{{% /since %}}

All durations are in nanoseconds.

{{% since "v1.12.0" %}}
`conn.handshake` covers resumed handshakes as well as full ones. A resumed
handshake is considerably cheaper, since it skips certificate verification and
access control, so a reload (which invalidates outstanding sessions, see
[Session Resumption]({{< ref "reloading.md#session-resumption" >}})) shows up
as a burst of slower handshakes.
{{% /since %}}

Ghostunnel also exports Go runtime metrics under `runtime.*`: gauges for
memory usage, goroutines, and garbage collection (refreshed every
`--metrics-interval`), and a `runtime.mem.gc.duration` timer of GC pause
durations.

The `--metrics-prefix` flag (default: `ghostunnel`) is prepended to all of
Ghostunnel's own metric names. It does not apply to the standard `go_*` and
`process_*` metrics on the Prometheus endpoint. How the prefix and metric
names are formatted depends on the output format (see below).

## JSON format (`/_metrics/json`)

JSON output uses dot-separated names. Counters and gauges are emitted as a
single value. Timers are expanded into count, mean, and percentile
sub-metrics:

| JSON metric name | Description |
|------------------|-------------|
| `ghostunnel.conn.open` | Gauge value |
| `ghostunnel.conn.handshake.count` | Number of observations |
| `ghostunnel.conn.handshake.mean` | Mean value |
| `ghostunnel.conn.handshake.50-percentile` | 50th percentile (median) |
| `ghostunnel.conn.handshake.75-percentile` | 75th percentile |
| `ghostunnel.conn.handshake.95-percentile` | 95th percentile |
| `ghostunnel.conn.handshake.99-percentile` | 99th percentile |

Ghostunnel v1.11.x and earlier also emit `min` and `max` for each
timer.{{% since "v1.12.0" %}} See [Migrating from v1.11.x](#migrating-from-v111x).{{% /since %}}

Each metric is returned as a JSON object with `timestamp`, `metric`, `value`,
and `hostname` fields.

## Prometheus format (`/_metrics/prometheus`)

Prometheus output replaces spaces, dots, dashes, `=`, and `/` in metric names
with underscores to comply with Prometheus naming conventions. The standard
`go_*` and `process_*` collectors from
[`client_golang`](https://github.com/prometheus/client_golang) are also
exported.

{{% since "v1.12.0" %}}
> **Changed in v1.12.0.** Metric types and timer series changed; see
> [Migrating from v1.11.x](#migrating-from-v111x).

### Ghostunnel v1.12.0 and later

Counters are exposed as Prometheus counters, `conn.open` and the `runtime.*`
gauges as gauges, and timers as
[histograms](https://prometheus.io/docs/concepts/metric_types/#histogram) with
`_bucket{le="..."}`, `_sum`, and `_count` series:

| Prometheus metric name | Description |
|------------------------|-------------|
| `ghostunnel_conn_open` | Current open connections (gauge) |
| `ghostunnel_accept_total` | Total connection attempts accepted (counter) |
| `ghostunnel_conn_handshake_bucket{le="..."}` | Cumulative count of handshakes ≤ the bucket boundary (nanoseconds) |
| `ghostunnel_conn_handshake_sum` | Sum of observed handshake durations |
| `ghostunnel_conn_handshake_count` | Number of observations |

Compute percentiles at query time with
[`histogram_quantile`](https://prometheus.io/docs/prometheus/latest/querying/functions/#histogram_quantile),
e.g. `histogram_quantile(0.99, rate(ghostunnel_conn_handshake_bucket[5m]))` for
a windowed p99. Each timer is also available as a
[native histogram](https://prometheus.io/docs/specs/native_histograms/) to
scrapers that request one.
{{% /since %}}

### Ghostunnel v1.11.x and earlier

All metrics are exposed as Prometheus gauges. Timers include statistical
gauges, rate gauges, and a histogram:

| Prometheus metric name | Description |
|------------------------|-------------|
| `ghostunnel_conn_open` | Current open connections |
| `ghostunnel_conn_handshake_count` | Number of observations |
| `ghostunnel_conn_handshake_sum` | Sum of observed values |
| `ghostunnel_conn_handshake_min` | Minimum value |
| `ghostunnel_conn_handshake_max` | Maximum value |
| `ghostunnel_conn_handshake_mean` | Mean value |
| `ghostunnel_conn_handshake_std_dev` | Standard deviation |
| `ghostunnel_conn_handshake_variance` | Variance |
| `ghostunnel_conn_handshake_rate1` | 1-minute rate |
| `ghostunnel_conn_handshake_rate5` | 5-minute rate |
| `ghostunnel_conn_handshake_rate15` | 15-minute rate |
| `ghostunnel_conn_handshake_rate_mean` | Mean rate |
| `ghostunnel_conn_handshake_timer_bucket{le="..."}` | Histogram buckets (0.50, 0.95, 0.99, 0.999) |
| `ghostunnel_conn_handshake_timer_count` | Histogram observation count |

### Prometheus scrape config

To scrape Ghostunnel metrics with Prometheus, add a job to your
`prometheus.yml`:

```yaml {file="prometheus.yml"}
scrape_configs:
  - job_name: ghostunnel
    scheme: https
    tls_config:
      ca_file: /path/to/cacert.pem
    metrics_path: /_metrics/prometheus
    static_configs:
      - targets: ['localhost:6060']
```

If the status port uses HTTP (see below), set `scheme: http` and drop the
`tls_config` block entirely.

## Metrics Export

Metrics are always available via the status port endpoints (`/_metrics/json`,
`/_metrics/prometheus`). Additionally, metrics can be pushed to external systems:

* `--metrics-graphite=ADDR`: push to a Graphite instance via raw TCP. Names
  are dot-separated as in JSON, with a suffix such as `.count`, `.value`, or
  `.99-percentile`.{{% since "v1.12.0" %}} Metrics are pushed at the interval
  set by `--metrics-interval` (default: 30s).{{% /since %}}
* `--metrics-url=URL`: push via HTTP POST (JSON format) at the interval set by
  `--metrics-interval` (default: 30s)

{{% since "v1.12.0" %}}
## Migrating from v1.11.x

Ghostunnel v1.12.0 uses a new metrics backend. Metric names are unchanged,
but some sub-metrics and how often they are pushed changed. The tables below
use `conn.handshake` as the example timer.

**Prometheus.** Counters are now Prometheus counters instead of gauges
(`conn.open` and the `runtime.*` metrics remain gauges). Timers are now
histograms:

| Field | v1.11.x | v1.12.0 |
|-------|:-------:|:-------:|
| `_count`, `_sum` | ✅ | ✅ |
| `_bucket{le="..."}` | ❌ | ✅ |
| native histogram | ❌ | ✅ |
| `_min`, `_max`, `_mean` | ✅ | ❌ |
| `_std_dev`, `_variance` | ✅ | ❌ |
| `_rate1`, `_rate5`, `_rate15`, `_rate_mean` | ✅ | ❌ |
| `_timer_bucket{le="..."}`, `_timer_count` | ✅ | ❌ (use `_bucket`/`_count`) |

**Graphite.** Metrics are pushed every `--metrics-interval` (default: 30s)
instead of every second. Counters no longer emit `.count_ps`. Timers keep
count, mean, and the main percentiles:

| Field | v1.11.x | v1.12.0 |
|-------|:-------:|:-------:|
| `count`, `mean` | ✅ | ✅ |
| `50/75/95/99-percentile` | ✅ | ✅ (bucket-interpolated) |
| `min`, `max` | ✅ | ❌ |
| `std-dev`, `999-percentile` | ✅ | ❌ |
| `count_ps`, `one-minute`, `five-minute`, `fifteen-minute`, `mean-rate` | ✅ | ❌ |

**JSON** (`/_metrics/json` and `--metrics-url`). Timers no longer emit `min`
and `max`:

| Field | v1.11.x | v1.12.0 |
|-------|:-------:|:-------:|
| `count`, `mean` | ✅ | ✅ |
| `50/75/95/99-percentile` | ✅ | ✅ (bucket-interpolated) |
| `min`, `max` | ✅ | ❌ |

Graphite and JSON percentile values may differ from earlier releases. They
used to come from a random sample of recent observations; they are now
interpolated from the histogram's buckets (the same method as PromQL's
`histogram_quantile`). Their precision depends on the bucket layout, and an
estimate above the highest bucket boundary is reported at that boundary. For
accurate, aggregatable percentiles, scrape the Prometheus endpoint and use
`histogram_quantile`.
{{% /since %}}

## Exposing Status Port with HTTP Instead of HTTPS

By default, Ghostunnel uses HTTPS for the status port. You can force it to use
HTTP by prefixing the status address with "http://".

For example:

```bash
# Status flag passed to Ghostunnel
ghostunnel server ... --status http://localhost:6060

# Status information (JSON)
curl http://localhost:6060/_status

# Metrics information (JSON)
curl http://localhost:6060/_metrics/json

# Metrics information (Prometheus)
curl http://localhost:6060/_metrics/prometheus
```
