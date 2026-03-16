Metrics & Profiling
===================

Ghostunnel has a notion of "status port", a TCP port (or UNIX socket) that can
be used to expose status and metrics information over HTTPS. The status port
feature can be controlled via the `--status` flag. Profiling endpoints on the
status port can be enabled with `--enable-pprof`.

The X.509 certificate on the status port will be the same as the certificate
used for proxying (either the client or server certificate). This means you can
use the status port to inspect/verify the certificate that is being used, which
can be useful for orchestration systems.

Example invocation with status port enabled:

    ghostunnel client \
        --listen localhost:8080 \
        --target localhost:8443 \
        --keystore test-keys/client-keystore.p12 \
        --cacert test-keys/cacert.pem \
        --status localhost:6060

Note that we set the status port to "localhost:6060". Ghostunnel will start an
internal HTTPS server and listen for connections on the given host/port. You
can also specify a UNIX socket instead of a TCP port.

How to check status and read connection metrics:

    # Status information (JSON)
    curl --cacert test-keys/cacert.pem https://localhost:6060/_status

    # Metrics information (JSON)
    curl --cacert test-keys/cacert.pem 'https://localhost:6060/_metrics/json'

    # Metrics information (Prometheus)
    curl --cacert test-keys/cacert.pem 'https://localhost:6060/_metrics/prometheus'

How to use profiling endpoints, if `--enable-pprof` is set:

    # Human-readable goroutine dump
    curl --cacert test-keys/cacert.pem 'https://localhost:6060/debug/pprof/goroutine?debug=1'

    # Analyze execution trace using pprof tool
    go tool pprof -seconds 5 https+insecure://localhost:6060/debug/pprof/profile

Note that `go tool pprof` does not support setting CA certificates at the
moment, hence the use of the `https+insecure` scheme in the last example. You
can use the standard `https` scheme if your Ghostunnel is using a certificate
trusted by your system (see [golang/go#20939][pprof-bug]). For more
information on profiling via pprof, see the [`runtime/pprof`][pprof] and
[`net/http/pprof`][http-pprof] docs.

[pprof]: https://pkg.go.dev/runtime/pprof
[http-pprof]: https://pkg.go.dev/net/http/pprof
[pprof-bug]: https://github.com/golang/go/issues/20939

### Shutdown endpoint

If `--enable-shutdown` is set, a `/_shutdown` endpoint is available on the
status port. Sending an HTTP POST request to this endpoint will trigger a
graceful shutdown of the Ghostunnel process. Any other HTTP method returns 405
Method Not Allowed.

### Backend healthchecks

The `/_status` endpoint includes a backend healthcheck. By default, Ghostunnel
performs a TCP connection check against the `--target` address. You can override
this with `--target-status=URL` to perform an HTTP GET against the given URL
instead. Ghostunnel expects an HTTP 200 response.

The `/_status` JSON response includes:

* `backend_ok` — boolean indicating if the backend check passed
* `backend_status` — string of `ok` or `critical`
* `backend_error` — string of error message if the check failed

If the backend check fails, the `/_status` endpoint returns HTTP 503.

### Metric names

Ghostunnel exports the following base metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `conn.open` | Gauge | Number of currently open connections |
| `conn.timeout` | Counter | Connections that timed out during data transfer |
| `accept.total` | Counter | Total connection attempts accepted |
| `accept.success` | Counter | Connections successfully established |
| `accept.error` | Counter | Failed connection attempts |
| `accept.timeout` | Counter | TLS handshake timeouts |
| `conn.handshake` | Timer | TLS handshake duration |
| `conn.lifetime` | Timer | Total connection lifetime |

The `--metrics-prefix` flag (default: `ghostunnel`) is prepended to all metric
names. How the prefix and metric names are formatted depends on the output
format (see below).

### JSON format (`/_metrics/json`)

JSON output uses dot-separated names. Counters and gauges are emitted as a
single value. Timers are expanded into count, min/max/mean, and percentile
sub-metrics:

| JSON metric name | Description |
|------------------|-------------|
| `ghostunnel.conn.open` | Counter value |
| `ghostunnel.conn.handshake.count` | Number of observations |
| `ghostunnel.conn.handshake.min` | Minimum value |
| `ghostunnel.conn.handshake.max` | Maximum value |
| `ghostunnel.conn.handshake.mean` | Mean value |
| `ghostunnel.conn.handshake.50-percentile` | 50th percentile (median) |
| `ghostunnel.conn.handshake.75-percentile` | 75th percentile |
| `ghostunnel.conn.handshake.95-percentile` | 95th percentile |
| `ghostunnel.conn.handshake.99-percentile` | 99th percentile |

Each metric is returned as a JSON object with `timestamp`, `metric`, `value`,
and `hostname` fields.

### Prometheus format (`/_metrics/prometheus`)

Prometheus output replaces dots, dashes, and other special characters with
underscores to comply with Prometheus naming conventions. All metrics are
exposed as Prometheus gauges. Timers additionally include rate gauges,
statistical gauges, and a summary histogram:

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

### Metrics export

Metrics are always available via the status port endpoints (`/_metrics/json`,
`/_metrics/prometheus`). Additionally, metrics can be pushed to external systems:

* `--metrics-graphite=ADDR` — push to a Graphite instance via raw TCP
  (dot-separated names, same as JSON format)
* `--metrics-url=URL` — push via HTTP POST (JSON format) at the interval set by
  `--metrics-interval` (default: 30s)

### Exposing status port with HTTP instead of HTTPS

By default, Ghostunnel uses HTTPS for the status port. You can force it to use
HTTP by prefixing the status address with "http://".

For example:

    # Status flag passed to Ghostunnel
    --status http://localhost:6060

    # Status information (JSON)
    curl http://localhost:6060/_status

    # Metrics information (JSON)
    curl http://localhost:6060/_metrics/json

    # Metrics information (Prometheus)
    curl http://localhost:6060/_metrics/prometheus
