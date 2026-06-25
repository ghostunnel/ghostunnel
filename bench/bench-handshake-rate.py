#!/usr/bin/env python3

"""
Connection-churn / mTLS handshake-rate benchmark for ghostunnel SERVER mode.

This exercises the core hot path: Accept -> TLS handshake -> client-cert verify
-> backend dial -> teardown (proxy/proxy.go). The load tool speaks HTTPS+mTLS to
ghostunnel, which terminates TLS, verifies the client cert, and forwards plain
HTTP to a tiny backend.

Two complementary signals (see bench/PLAN.md "Risks"):

  * openssl s_time (ALWAYS available, AUTHORITATIVE) -- single-threaded, so it
    measures the *serial, round-trip-bound* handshake rate. `-new` forces a full
    handshake each connection; `-reuse` measures resumed handshakes. This is the
    ground-truth full-vs-resumed signal.

  * vegeta -keepalive=false (parallel/peak, may be missing -> skipped) -- opens a
    fresh TCP connection per request to drive connection churn at scale, measuring
    parallel connection-cycling throughput. IMPORTANT: this is NOT a clean
    full-handshake measurement, and we do NOT pretend it is. ghostunnel cannot
    distinguish full from resumed handshakes (its conn.handshake.count increments
    for both), and Go's TLS client caches session tickets, so most cycled
    connections likely RESUME rather than perform a full handshake. ghostunnel
    also exposes no flag to disable resumption server-side. So: treat openssl
    s_time -new as the authoritative full-handshake rate, and read the vegeta
    number as "peak parallel conn-cycling throughput (TLS composition
    uncontrolled)". The conn.handshake.count cross-check below only confirms
    ghostunnel did ~one handshake per request (i.e. connections really cycled and
    keepalive=false was honored) -- it canNOT and does not detect resumption.

Sweep: cert algorithm (ecdsa / rsa / ed25519) x, for s_time, resumption
(new / reuse). Each measured point is the median over ENV["runs"] passes after a
discarded ENV["warmup"] pass, each of ENV["duration"] seconds.

Run directly:  python3 bench-handshake-rate.py
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) or "."))
import bench_common as bc  # noqa: E402

# --- vegeta load constants (parallel/peak signal) -------------------------
VEGETA_RATE = 2000          # requests/sec the open-model attacker tries to issue
VEGETA_MAX_WORKERS = 50     # cap on concurrent in-flight connections

ALGORITHMS = ["ecdsa", "rsa", "ed25519"]

# Sanity threshold for the connection-cycling cross-check: with keepalive=false
# each request should produce its own handshake, so handshakes/requests should be
# ~1.0. A ratio well below this floor means connections were unexpectedly reused
# (keepalive not honored) or the status scrape failed -- NOT a resumption signal
# (ghostunnel counts resumed handshakes too; see the module docstring).
HANDSHAKE_RATIO_FLOOR = 0.5

# Handshake-count metric exposed at /_metrics/json (go-metrics Timer).
HANDSHAKE_COUNT_METRIC = "ghostunnel.conn.handshake.count"


def median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return None
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


# ---------------------------------------------------------------------------
# openssl s_time -- serial, authoritative full-vs-resumed handshake rate
# ---------------------------------------------------------------------------

_STIME_RE = re.compile(r"(\d+)\s+connections in\s+([\d.]+)\s+real seconds")


def parse_s_time(stdout):
    """Return conns/sec from an `openssl s_time` run.

    s_time can print two "connections in ..." lines; only the one mentioning
    "real seconds" is the wall-clock figure we want. Returns (conns, secs, rate)
    or None if it can't be parsed.
    """
    match = None
    for line in stdout.splitlines():
        m = _STIME_RE.search(line)
        if m:
            match = m  # keep the last match (the "real seconds" line)
    if not match:
        return None
    conns = int(match.group(1))
    secs = float(match.group(2))
    if secs <= 0:
        return None
    return conns, secs, conns / secs


def run_s_time(openssl, certs, listen, mode, duration, tls_flag=None):
    """One `openssl s_time` pass. mode is "new" or "reuse". Returns rate or None."""
    cmd = [
        openssl, "s_time",
        "-connect", bc.addr_str(listen),
        "-cert", certs.client_crt,
        "-key", certs.client_key,
        "-CAfile", certs.ca,
        "-www", "/",
        "-" + mode,                 # -new (full) or -reuse (resumed)
        "-time", str(duration),
    ]
    if tls_flag:
        cmd.append(tls_flag)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    parsed = parse_s_time(proc.stdout)
    if parsed is None:
        bc.print_err("s_time parse failed (mode={0}):\n{1}\n{2}".format(
            mode, proc.stdout[-400:], proc.stderr[-400:]))
        return None
    return parsed[2]


def bench_s_time(openssl, certs, topo, algo, tls_label, tls_flag):
    """Run the s_time new/reuse sweep for one algorithm and emit two results."""
    for mode in ("new", "reuse"):
        # Discarded warmup pass.
        if bc.ENV["warmup"] > 0:
            run_s_time(openssl, certs, topo.listen, mode,
                       bc.ENV["warmup"], tls_flag)

        rates = []
        for _ in range(bc.ENV["runs"]):
            rate = run_s_time(openssl, certs, topo.listen, mode,
                              bc.ENV["duration"], tls_flag)
            if rate is not None:
                rates.append(rate)

        if not rates:
            bc.print_err("s_time produced no measurements ({0}/{1}/{2})".format(
                algo, mode, tls_label))
            continue

        med = median(rates)
        bc.write_result(bc.Result(
            bench="handshake-rate",
            params={
                "algorithm": algo,
                "tool": "openssl-s_time",
                "resumption": mode,
                "tls": tls_label,
            },
            metric={"primary": med, "unit": "handshakes/s"},
            raw={
                "runs": rates,
                "run_count": len(rates),
                "rate_per_sec": med,
                "vegeta_rate": None,
            }))


# ---------------------------------------------------------------------------
# vegeta -- parallel/peak signal, with the resumption-masking cross-check
# ---------------------------------------------------------------------------

def run_vegeta(vegeta, certs, listen, duration):
    """One `vegeta attack | vegeta report -type=json` pass. Returns parsed dict."""
    target = "GET https://{0}/".format(bc.addr_str(listen))
    attack = [
        vegeta, "attack",
        "-cert", certs.client_crt,
        "-key", certs.client_key,
        "-root-certs", certs.ca,
        "-keepalive=false",
        "-rate", str(VEGETA_RATE),
        "-duration", "{0}s".format(duration),
        "-max-workers", str(VEGETA_MAX_WORKERS),
    ]
    report = [vegeta, "report", "-type=json"]

    attack_proc = subprocess.Popen(
        attack, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    report_proc = subprocess.Popen(
        report, stdin=attack_proc.stdout, stdout=subprocess.PIPE, text=True)
    attack_proc.stdout.close()  # let report own the pipe / get EOF
    attack_proc.stdin.write((target + "\n").encode())
    attack_proc.stdin.close()
    out, _ = report_proc.communicate()
    attack_proc.wait()

    import json
    try:
        return json.loads(out)
    except Exception as e:
        bc.print_err("vegeta report parse failed: {0}\n{1}".format(e, out[-400:]))
        return None


def bench_vegeta(vegeta, certs, topo, algo, tls_label):
    """Run vegeta keepalive=false, emit one result, and cross-check resumption."""
    # Discarded warmup pass.
    if bc.ENV["warmup"] > 0:
        run_vegeta(vegeta, certs, topo.listen, bc.ENV["warmup"])

    reports = []
    for _ in range(bc.ENV["runs"]):
        # Snapshot the handshake counter before/after so the cross-check is
        # scoped to just this measured pass.
        before = handshake_count(topo)
        rep = run_vegeta(vegeta, certs, topo.listen, bc.ENV["duration"])
        after = handshake_count(topo)
        if rep is not None:
            rep["_handshake_delta"] = (
                None if before is None or after is None else after - before)
            reports.append(rep)

    if not reports:
        bc.print_err("vegeta produced no measurements ({0}/{1})".format(
            algo, tls_label))
        return

    # Pick the median-throughput pass as representative.
    reports.sort(key=lambda r: r.get("throughput", 0.0))
    rep = reports[len(reports) // 2]

    throughput = rep.get("throughput", 0.0)            # req/s completed
    requests = rep.get("requests", VEGETA_RATE * bc.ENV["duration"])
    lat = rep.get("latencies", {}) or {}

    def to_ms(ns):
        return None if ns is None else ns / 1e6

    # Connection-cycling sanity check (NOT a resumption detector -- see docstring).
    # ghostunnel counts full and resumed handshakes the same, so this ratio is
    # ~1.0 whenever connections cycle, regardless of resumption. It only catches
    # the degenerate case where connections were reused (keepalive ignored) or the
    # scrape failed.
    handshake_delta = rep.get("_handshake_delta")
    cycling_ratio = None
    conn_cycling_ok = None
    if handshake_delta is not None and requests > 0:
        cycling_ratio = handshake_delta / float(requests)
        conn_cycling_ok = cycling_ratio >= HANDSHAKE_RATIO_FLOOR
        if not conn_cycling_ok:
            bc.print_err(
                "WARNING ({0}/{1}): ghostunnel saw {2} handshakes for {3} "
                "requests (ratio {4:.2f}); connections may not be cycling as "
                "expected (keepalive not honored?) or the scrape failed.".format(
                    algo, tls_label, handshake_delta, requests, cycling_ratio))

    bc.write_result(bc.Result(
        bench="handshake-rate",
        params={
            "algorithm": algo,
            "tool": "vegeta",
            "resumption": "keepalive-false",
            "tls": tls_label,
        },
        metric={
            "primary": throughput,
            "unit": "req/s",
            "measures": "parallel conn-cycling throughput (TLS composition "
                        "uncontrolled; see openssl-s_time/new for authoritative "
                        "full-handshake rate)",
            "p50": to_ms(lat.get("50th")),
            "p95": to_ms(lat.get("95th")),
            "p99": to_ms(lat.get("99th")),
        },
        raw={
            "vegeta_rate": VEGETA_RATE,
            "vegeta_max_workers": VEGETA_MAX_WORKERS,
            "requests": requests,
            "success": rep.get("success"),
            "status_codes": rep.get("status_codes"),
            "throughput_req_per_sec": throughput,
            "latency_mean_ms": to_ms(lat.get("mean")),
            "latency_max_ms": to_ms(lat.get("max")),
            "handshake_count_delta": handshake_delta,
            "handshakes_per_request": cycling_ratio,
            "conn_cycling_ok": conn_cycling_ok,
            "note": "ghostunnel cannot distinguish full vs resumed handshakes; "
                    "this number is not a full-handshake rate. Use the "
                    "openssl-s_time -new result for that.",
        }))


def handshake_count(topo):
    """Current ghostunnel.conn.handshake.count from the server status port."""
    try:
        metrics = topo.scrape("server")
    except Exception as e:
        bc.print_err("status scrape failed: {0}".format(e))
        return None
    val = metrics.get(HANDSHAKE_COUNT_METRIC)
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_algorithm(openssl, vegeta, algo):
    """Generate certs, stand up the server topology, run both tools."""
    try:
        certs = bc.gen_certs(algo)
    except SystemExit:
        # gen_certs exits 2 for an unsupported algorithm (e.g. ed25519). Don't
        # let that abort the whole run -- just skip this one.
        bc.print_err("skipping algorithm {0} (cert generation unavailable)".format(algo))
        return

    # tls_max=None -> Go default (TLS 1.3), the priority case.
    tls_label = "1.3"
    topo = bc.start_server_topology(certs, tls_max=None, resp_size=64)
    try:
        bench_s_time(openssl, certs, topo, algo, tls_label, tls_flag="-tls1_3")
        if vegeta:
            bench_vegeta(vegeta, certs, topo, algo, tls_label)
    finally:
        topo.teardown()
        certs.cleanup()


def main():
    # openssl s_time is the authoritative signal and must be present; if it is
    # missing there is nothing to measure, so SKIP (exit 2).
    openssl = bc.require_tool("openssl")

    # vegeta is optional: if absent we still run the s_time sweep and exit 0.
    import shutil
    vegeta = shutil.which("vegeta")
    if not vegeta:
        bc.print_err("note: 'vegeta' not found on PATH -- running openssl "
                     "s_time only (parallel/peak signal skipped)")

    for algo in ALGORITHMS:
        run_algorithm(openssl, vegeta, algo)

    return 0


if __name__ == "__main__":
    sys.exit(main())
