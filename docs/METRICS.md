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
    curl --cacert test-keys/cacert.pem 'https://localhost:6060/_metrics?format=json'
    
    # Metrics information (Prometheus)
    curl --cacert test-keys/cacert.pem 'https://localhost:6060/_metrics/prometheus'

How to use profiling endpoints, if `--enable-pprof` is set:

    # Human-readable goroutine dump
    curl --cacert test-keys/cacert.pem 'https://localhost:6060/debug/pprof/goroutine?debug=1'

    # Analyze execution trace using pprof tool
    go tool pprof -seconds 5 https+insecure://localhost:6060/debug/pprof/profile

Note that `go tool pprof` does not support setting CA certificates at the
moment, hence the use of the `https+insecure` scheme in the last example. You
can use the standard `https` scheme if your ghostunnel is using a certificate
trusted by your system (c.f. [golang/go#20939][pprof-bug]). For more
information on profiling via pprof, see the [`runtime/pprof`][pprof] and
[`net/http/pprof`][http-pprof] docs.

[pprof]: https://golang.org/pkg/runtime/pprof
[http-pprof]: https://golang.org/pkg/net/http/pprof
[pprof-bug]: https://github.com/golang/go/issues/20939

