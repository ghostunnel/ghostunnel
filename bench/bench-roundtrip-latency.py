#!/usr/bin/env python3

"""
Round-trip latency benchmark for ghostunnel SERVER mode (concurrent, keep-alive).

Measures steady-state request/response round-trip latency under concurrent load
through ghostunnel acting as an mTLS-terminating reverse proxy. Keep-alive is ON,
so the TLS handshake is amortized across many requests on each connection and we
measure per-request latency in steady state rather than handshake cost. The
"many concurrent connections" axis is exercised via vegeta's -max-workers cap.

Topology (start_server_topology):

    vegeta (HTTPS + mTLS, keep-alive)  ->  ghostunnel server (TLS terminate, mTLS)
                                       ->  plain-HTTP backend (64-byte response)

Tool: vegeta (https://github.com/tsenart/vegeta). Invocation per measured pass:

    echo "GET https://HOST:PORT/" | \\
      vegeta attack -cert CLIENT_CRT -key CLIENT_KEY -root-certs CA \\
        -keepalive=true -rate R -duration Ds -max-workers W | \\
      vegeta report -type=json

vegeta's report JSON exposes a `latencies` object with `mean`/`50th`/`95th`/
`99th`/`max` in NANOSECONDS, plus `throughput`, `rate`, `success`,
`status_codes`, and `errors`. We convert latencies ns -> ms for reporting.

=============================================================================
CRITICAL FRAMING — vegeta is an OPEN-MODEL, rate-driven generator
=============================================================================
You set `-rate` (requests/second); vegeta tries to *issue* that many requests
per second regardless of how fast they complete. It is NOT a fixed-concurrency
closed loop. `-max-workers` only caps the number of in-flight connections.

Consequence (see PLAN.md "Risks"): if the offered rate exceeds what ghostunnel
can actually serve, requests queue, in-flight workers saturate, and reported
latency blows up — the classic coordinated-omission failure mode. A single
latency number is therefore meaningless without the rate it was measured at.

So this benchmark:
  * ALWAYS reports the offered rate alongside every percentile (it is a param);
  * SWEEPS the rate to find the "knee" where latency degrades, rather than
    quoting one number;
  * flags overload (success < 0.99 or non-empty errors) explicitly in `raw`.
=============================================================================
"""

import json
import statistics
import subprocess
import sys

import bench_common as bc

# ---------------------------------------------------------------------------
# Sweep constants (adjustable). Keep the matrix small: latency is dominated by
# steady-state per-request cost, not the handshake, so we fix the algorithm to
# ECDSA (P-256) as the priority and optionally add a single RSA run.
# ---------------------------------------------------------------------------

# Offered request rates (req/s). Sweep to locate the latency knee — do NOT read
# any single point in isolation (vegeta is open-model; see module docstring).
RATES = [500, 2000, 8000]

# In-flight connection cap (vegeta -max-workers). This is the "many concurrent
# connections" axis.
MAX_WORKERS = [16, 64, 256]

# Cert/key algorithms to sweep. ECDSA is the priority; RSA is an optional extra.
ALGORITHMS = ["ecdsa"]
# To also measure RSA, uncomment the next line (steady-state latency should be
# nearly identical to ECDSA since the handshake is amortized over keep-alive):
# ALGORITHMS = ["ecdsa", "rsa"]

# Default Go TLS (1.3). None -> do not pass --max-tls-version (Go default).
TLS_MAX = None

NS_PER_MS = 1_000_000.0


def _tls_label(tls_max):
    return tls_max if tls_max else "default"


def run_vegeta(vegeta, listen, certs, *, rate, duration, max_workers):
    """Run one vegeta attack+report pass; return the parsed report JSON dict.

    Raises subprocess.CalledProcessError / json.JSONDecodeError on failure so the
    caller can decide how to handle a broken pass.
    """
    target = 'GET https://{0}:{1}/'.format(listen[0], listen[1])
    attack = subprocess.Popen(
        [
            vegeta, "attack",
            "-cert", certs.client_crt,
            "-key", certs.client_key,
            "-root-certs", certs.ca,
            "-keepalive=true",
            "-rate", str(rate),
            "-duration", "{0}s".format(duration),
            "-max-workers", str(max_workers),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    report = subprocess.Popen(
        [vegeta, "report", "-type=json"],
        stdin=attack.stdout,
        stdout=subprocess.PIPE,
    )
    # Allow attack to receive SIGPIPE if report exits, per subprocess docs.
    attack.stdout.close()
    attack.stdin.write(target.encode())
    attack.stdin.close()
    out, _ = report.communicate()
    attack.wait()
    if report.returncode != 0:
        raise subprocess.CalledProcessError(report.returncode, "vegeta report")
    return json.loads(out.decode())


def _lat_ms(report, key):
    """Pull a latency percentile (ns) out of a vegeta report and convert to ms."""
    return report.get("latencies", {}).get(key, 0) / NS_PER_MS


def _scrape_summary(topo):
    """Best-effort ghostunnel-side cross-check metrics for the `raw` block."""
    try:
        m = topo.scrape("server")
    except Exception as e:
        return {"scrape_error": str(e)}
    summary = {}
    # conn.open / accept.success are counters; record whatever the metric value
    # carries (sqmetrics emits either a scalar or a per-metric dict).
    for name in ("ghostunnel.conn.open", "ghostunnel.accept.success"):
        if name in m:
            summary[name] = m[name]
    # conn.lifetime is a timer: record its percentile breakdown if present.
    for name in m:
        if name.startswith("ghostunnel.conn.lifetime"):
            summary[name] = m[name]
    return summary


def measure(vegeta, topo, certs, *, rate, max_workers, runs, duration):
    """Run `runs` measured passes; return (medians dict, last report, raw scrape)."""
    p50s, p95s, p99s, tputs, succs = [], [], [], [], []
    last = None
    overload = False
    errors_seen = []

    for i in range(runs):
        report = run_vegeta(
            vegeta, topo.listen, certs,
            rate=rate, duration=duration, max_workers=max_workers)
        last = report

        success = report.get("success", 0.0)
        errs = report.get("errors") or []
        # Overload detection: open-model rate exceeded served capacity.
        if success < 0.99 or errs:
            overload = True
            if errs:
                errors_seen.extend(errs)

        p50s.append(_lat_ms(report, "50th"))
        p95s.append(_lat_ms(report, "95th"))
        p99s.append(_lat_ms(report, "99th"))
        tputs.append(report.get("throughput", 0.0))
        succs.append(success)

    medians = {
        "p50": statistics.median(p50s),
        "p95": statistics.median(p95s),
        "p99": statistics.median(p99s),
        "throughput": statistics.median(tputs),
        "success": statistics.median(succs),
    }
    raw = {
        "rate_offered": rate,
        "max_workers": max_workers,
        "runs": runs,
        "duration_s": duration,
        "vegeta": {
            "latencies_ms": {
                "mean": _lat_ms(last, "mean"),
                "p50": _lat_ms(last, "50th"),
                "p95": _lat_ms(last, "95th"),
                "p99": _lat_ms(last, "99th"),
                "max": _lat_ms(last, "max"),
            },
            "throughput_rps": last.get("throughput"),
            "rate_achieved": last.get("rate"),
            "success": last.get("success"),
            "status_codes": last.get("status_codes"),
            "errors": last.get("errors"),
        },
        "samples": {
            "p50_ms": p50s, "p95_ms": p95s, "p99_ms": p99s,
            "throughput_rps": tputs, "success": succs,
        },
        "ghostunnel": _scrape_summary(topo),
        "overload": overload,
    }
    if errors_seen:
        raw["overload_errors"] = errors_seen
    return medians, raw, overload


def run_algorithm(vegeta, algo, *, runs, duration, warmup):
    """Build one topology for `algo` and sweep (rate, max_workers) over it."""
    certs = bc.gen_certs(algo)
    tls_label = _tls_label(TLS_MAX)
    topo = bc.start_server_topology(
        certs, tls_max=TLS_MAX, max_conns=0, resp_size=64)
    try:
        # Discarded warmup pass (amortize handshakes, warm pools/JITless Go GC,
        # settle the scheduler) at the middle rate / widest worker cap.
        if warmup > 0:
            warm_rate = RATES[len(RATES) // 2]
            warm_workers = MAX_WORKERS[-1]
            bc.print_ok(
                "[{0}] warmup: rate={1} workers={2} {3}s (discarded)".format(
                    algo, warm_rate, warm_workers, warmup))
            try:
                run_vegeta(vegeta, topo.listen, certs,
                           rate=warm_rate, duration=warmup,
                           max_workers=warm_workers)
            except Exception as e:
                bc.print_err("[{0}] warmup failed (continuing): {1}".format(algo, e))

        for rate in RATES:
            for workers in MAX_WORKERS:
                bc.print_ok(
                    "[{0}] measuring: rate={1} max_workers={2} "
                    "({3} runs x {4}s)".format(
                        algo, rate, workers, runs, duration))
                medians, raw, overload = measure(
                    vegeta, topo, certs,
                    rate=rate, max_workers=workers,
                    runs=runs, duration=duration)

                if overload:
                    bc.print_err(
                        "[{0}] OVERLOAD at rate={1} workers={2}: "
                        "success={3:.4f} — offered rate likely exceeds "
                        "ghostunnel capacity; latency is coordinated-omission "
                        "inflated, treat percentiles as a lower bound.".format(
                            algo, rate, workers, medians["success"]))

                bc.write_result(bc.Result(
                    bench="roundtrip-latency",
                    params={
                        "rate": rate,
                        "max_workers": workers,
                        "algorithm": algo,
                        "tls": tls_label,
                    },
                    metric={
                        "primary": medians["p50"],
                        "unit": "ms",
                        "p50": medians["p50"],
                        "p95": medians["p95"],
                        "p99": medians["p99"],
                        "throughput_rps": medians["throughput"],
                        "success": medians["success"],
                    },
                    raw=raw))
    finally:
        topo.teardown()
        certs.cleanup()


def main():
    # Preflight: skip cleanly (exit 2 -> mage reports SKIP) if vegeta is absent.
    vegeta = bc.require_tool("vegeta")

    runs = bc.ENV["runs"]
    duration = bc.ENV["duration"]
    warmup = bc.ENV["warmup"]

    for algo in ALGORITHMS:
        # Rebuild the topology per algorithm (fresh certs); reuse it across the
        # rate/worker sweep for that algorithm.
        run_algorithm(vegeta, algo, runs=runs, duration=duration, warmup=warmup)


if __name__ == "__main__":
    main()
