#!/usr/bin/env python3

"""
Steady-state bulk throughput benchmark for the ghostunnel external-binary suite.

Measures plaintext throughput (Gbit/s) carried through an mTLS ghostunnel tunnel,
exercising the proxy copyData/io.CopyBuffer hot path and TLS record crypto.

Topology (start_fullchain_topology): both iperf3 ends are plain TCP, TLS in the
middle:

    iperf3 -c  ->  topo.listen (ghostunnel CLIENT, plain TCP)  -> TLS ->
                   ghostunnel SERVER  ->  topo.backend (iperf3 -s, plain TCP)

For each parallel-stream count we measure THROUGH the tunnel (iperf3 -c against
topo.listen) and a BASELINE direct to iperf3 -s (iperf3 -c against topo.backend,
no tunnel). Because both paths move the same plaintext bytes, the baseline/tunnel
ratio IS a meaningful like-for-like overhead delta (per PLAN.md).

iperf3 detail: a single `iperf3 -s` serves ONE client at a time, so baseline and
tunnel measurements are run STRICTLY SEQUENTIALLY (never concurrently against the
same server), with a brief sleep between runs so the server frees up.

Tool: iperf3 (skip-with-reason via sys.exit(2) if missing).
"""

import json
import subprocess
import sys
import time

import bench_common as bc

# Concurrency axis: iperf3 parallel streams (-P).
STREAM_COUNTS = [1, 4]

# Brief settle between sequential iperf3 runs so the single -s server frees up.
_IPERF_SETTLE = 0.5


def _run_iperf(host, port, duration, streams):
    """Run one iperf3 client pass; return the parsed JSON dict.

    Raises on non-zero exit or unparseable / error JSON so a broken run never
    masquerades as a (bogus) measurement.
    """
    cmd = ["iperf3", "-c", host, "-p", str(port),
           "-t", str(duration), "-P", str(streams), "-J"]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        data = json.loads(proc.stdout.decode() or "{}")
    except ValueError:
        raise RuntimeError(
            "iperf3 produced unparseable output (rc={0}): {1}".format(
                proc.returncode, proc.stderr.decode()[:500]))
    if data.get("error"):
        raise RuntimeError("iperf3 error: {0}".format(data["error"]))
    if proc.returncode != 0:
        raise RuntimeError("iperf3 exited {0}: {1}".format(
            proc.returncode, proc.stderr.decode()[:500]))
    return data


def _summarize(data):
    """Extract a compact summary from an iperf3 -J result.

    Prefer end.sum_received (receiver-side, the canonical goodput); fall back to
    end.sum if a particular iperf3 build omits sum_received.
    """
    end = data.get("end", {})
    summ = end.get("sum_received") or end.get("sum") or {}
    bits_per_second = summ.get("bits_per_second", 0.0)
    out = {
        "bits_per_second": bits_per_second,
        "gbit_per_second": bits_per_second / 1e9,
        "bytes": summ.get("bytes"),
        "seconds": summ.get("seconds"),
    }
    # Retransmits live on the sender side (end.sum_sent / end.sum).
    sent = end.get("sum_sent") or end.get("sum") or {}
    if "retransmits" in sent:
        out["retransmits"] = sent["retransmits"]
    return out


def _measure(host, port, label):
    """Warmup (discarded) + ENV['runs'] measured passes; return (median_gbit, summaries).

    Runs are strictly sequential with a settle gap so a single iperf3 -s is never
    hit concurrently.
    """
    duration = bc.ENV["duration"]
    warmup = bc.ENV["warmup"]
    runs = max(1, bc.ENV["runs"])

    if warmup > 0:
        bc.print_ok("{0}: warmup ({1}s, discarded)".format(label, warmup))
        _run_iperf(host, port, warmup, _measure.streams)
        time.sleep(_IPERF_SETTLE)

    summaries = []
    gbits = []
    for i in range(runs):
        bc.print_ok("{0}: measured run {1}/{2} ({3}s)".format(
            label, i + 1, runs, duration))
        data = _run_iperf(host, port, duration, _measure.streams)
        summ = _summarize(data)
        summaries.append(summ)
        gbits.append(summ["gbit_per_second"])
        if i < runs - 1:
            time.sleep(_IPERF_SETTLE)

    gbits.sort()
    median = gbits[len(gbits) // 2]
    return median, summaries


def _accept_count(metrics):
    """Pull ghostunnel.accept.success as a number (metric value may be a dict)."""
    val = metrics.get("ghostunnel.accept.success")
    if isinstance(val, dict):
        val = val.get("value", val.get("count", 0))
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0.0


def main():
    # Preflight: clean SKIP before building anything if iperf3 is absent.
    # (start_fullchain_topology also calls require_tool, but checking here keeps
    # the skip cheap and obvious.)
    bc.require_tool("iperf3")

    certs = bc.gen_certs("ecdsa")

    tls_max = None                       # Go default (TLS 1.3)
    tls_label = tls_max or "default"

    topo = bc.start_fullchain_topology(certs, tls_max=tls_max)
    try:
        for streams in STREAM_COUNTS:
            _measure.streams = streams

            # --- BASELINE: direct to iperf3 -s, no tunnel (run FIRST, alone) ---
            base_gbit, base_summaries = _measure(
                topo.backend[0], topo.backend[1],
                "baseline P={0}".format(streams))

            time.sleep(_IPERF_SETTLE)

            # --- TUNNEL: through ghostunnel client -> server -> iperf3 -s ---
            accept_before = _accept_count(topo.scrape("server"))
            tunnel_gbit, tunnel_summaries = _measure(
                topo.listen[0], topo.listen[1],
                "tunnel P={0}".format(streams))
            accept_after = _accept_count(topo.scrape("server"))

            accept_delta = accept_after - accept_before

            # --- Cross-checks: ghostunnel actually carried the traffic ---
            if accept_delta <= 0:
                bc.print_err(
                    "WARNING streams={0}: ghostunnel.accept.success did not "
                    "increase ({1} -> {2}); tunnel traffic may not have gone "
                    "through ghostunnel".format(
                        streams, accept_before, accept_after))
            if tunnel_gbit <= 0:
                bc.print_err(
                    "WARNING streams={0}: tunnel throughput is {1} Gbit/s "
                    "(expected > 0)".format(streams, tunnel_gbit))
            if base_gbit > 0 and tunnel_gbit > base_gbit * 1.05:
                # Small slack for measurement noise; tunnel should not beat the
                # direct baseline by a meaningful margin.
                bc.print_err(
                    "WARNING streams={0}: tunnel {1:.3f} Gbit/s exceeds baseline "
                    "{2:.3f} Gbit/s (unexpected)".format(
                        streams, tunnel_gbit, base_gbit))

            overhead_ratio = (base_gbit / tunnel_gbit) if tunnel_gbit > 0 else None

            bc.write_result(bc.Result(
                bench="throughput",
                params={"streams": streams, "tls": tls_label},
                metric={
                    "primary": tunnel_gbit,
                    "unit": "Gbit/s",
                    "baseline_gbit": base_gbit,
                    "overhead_ratio": overhead_ratio,
                    "runs": bc.ENV["runs"],
                },
                raw={
                    "duration_s": bc.ENV["duration"],
                    "warmup_s": bc.ENV["warmup"],
                    "streams": streams,
                    "tunnel": {
                        "median_gbit": tunnel_gbit,
                        "runs": tunnel_summaries,
                    },
                    "baseline": {
                        "median_gbit": base_gbit,
                        "runs": base_summaries,
                    },
                    "accept_success_before": accept_before,
                    "accept_success_after": accept_after,
                    "accept_success_delta": accept_delta,
                }))

            time.sleep(_IPERF_SETTLE)
    finally:
        topo.teardown()


if __name__ == "__main__":
    main()
