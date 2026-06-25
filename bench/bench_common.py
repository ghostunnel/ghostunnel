#!/usr/bin/env python3

"""
Shared helpers + topology builders for the ghostunnel external-binary benchmark
suite. See bench/PLAN.md for the design.

This module deliberately does NOT import tests/common.py: that module has import
side effects (chdir into a temp dir, allocate three process-global ports). The
benchmark needs multiple ghostunnel instances per process, so we reuse the
*patterns* (the openssl cert recipe, get_free_port, /_status polling) here with
per-endpoint port allocation.

=============================================================================
CONTRACT (frozen for Phase-1 benchmark scripts — code against these only):
=============================================================================

  build_release_binary() -> str
      Build (once per process) and return the absolute path to a plain,
      non-coverage `ghostunnel.bench` binary. Honors $GHOSTUNNEL_GO.

  gen_certs(algorithm="ecdsa") -> CertSet
      Generate a CA + server + client cert chain (all PEM) in a fresh temp dir.
      algorithm in {"ecdsa", "rsa", "ed25519"}. Client/server OU == "client"/
      "server" (so ghostunnel --allow-ou=client accepts the client). Fields:
        .dir .ca .server_crt .server_key .client_crt .client_key .algorithm
      Call .cleanup() when done (also runs at exit).

  start_server_topology(certs, *, tls_max=None, max_conns=0, resp_size=64) -> Topology
      Launch: HTTP backend  +  one ghostunnel SERVER (mTLS).
      Load tool speaks HTTPS+mTLS to topo.listen; ghostunnel forwards plain HTTP
      to the backend. Fields: .listen (host,port) .status (host,port)
      .backend (host,port) .server_status == .status. Use .scrape() / .teardown().

  start_fullchain_topology(certs, *, tls_max=None) -> Topology
      Launch: iperf3 -s  +  ghostunnel SERVER  +  ghostunnel CLIENT.
      Plain TCP in/out, TLS in the middle. iperf3 -c connects to topo.listen.
      Fields: .listen (the client listen addr) .client_status .server_status
      .backend (iperf3 -s addr). Use .scrape(which="server"|"client") / .teardown().

  wait_ready(status_addr, timeout=30) -> None
      Poll https://host:port/_status (TLS, no verify) until it answers.

  require_tool(name) -> str
      Return the tool's path, or sys.exit(2) with a skip reason if missing
      (mage reports SKIP for exit code 2).

  scrape_status(status_addr) -> dict
      Fetch /_metrics/json from a status port; return {metric_name: value}.

  Result(bench, params, metric, raw=None)  +  write_result(result) -> str
      Normalized JSON+CSV emitter (schema in PLAN.md). Returns the JSON path.

  Helpers: get_free_port(), alloc_endpoint(), print_ok(), print_err(),
           require_platform(*systems), ENV (duration/runs/warmup).
=============================================================================
"""

import atexit
import csv
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field, asdict

LOCALHOST = "127.0.0.1"
IS_WINDOWS = platform.system() == "Windows"

_BENCH_DIR = os.path.abspath(os.path.dirname(__file__) or ".")
_ROOT_DIR = os.path.abspath(os.path.join(_BENCH_DIR, ".."))
_RESULTS_DIR = os.path.join(_BENCH_DIR, "results")
_HTTP_BACKEND = os.path.join(_BENCH_DIR, "http_backend.py")

# Tunables shared by all benchmarks (env-overridable, mirrors GHOSTUNNEL_TEST_*).
ENV = {
    "duration": int(os.environ.get("GHOSTUNNEL_BENCH_DURATION", "10")),
    "runs": int(os.environ.get("GHOSTUNNEL_BENCH_RUNS", "3")),
    "warmup": int(os.environ.get("GHOSTUNNEL_BENCH_WARMUP", "2")),
}

_SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", None)
_port_reservations = []  # keep reservation sockets open for process lifetime
atexit.register(lambda: [s.close() for s in _port_reservations])


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_ok(msg):
    print("\033[92m{0}\033[0m".format(msg), file=sys.stderr, flush=True)


def print_err(msg):
    print("\033[91m{0}\033[0m".format(msg), file=sys.stderr, flush=True)


def require_platform(*systems):
    if platform.system() not in systems:
        print_err("skipping: requires platform {0}".format(systems))
        sys.exit(2)


def require_tool(name):
    """Return path to an external tool, or skip (exit 2) if it's not installed."""
    path = shutil.which(name)
    if not path:
        print_err("skipping: required tool '{0}' not found on PATH".format(name))
        sys.exit(2)
    return path


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

def get_free_port(release=False):
    """Allocate a free TCP port on loopback.

    On platforms with SO_REUSEPORT the reservation socket stays open for the
    process lifetime (so concurrent benches don't collide and a SO_REUSEPORT
    binder — ghostunnel or our http_backend — can co-bind); elsewhere it's
    released immediately. Pass release=True for a port handed to a process we
    can't make set SO_REUSEPORT (e.g. iperf3), accepting a small TOCTOU race.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if _SO_REUSEPORT is not None:
        s.setsockopt(socket.SOL_SOCKET, _SO_REUSEPORT, 1)
    s.bind((LOCALHOST, 0))
    port = s.getsockname()[1]
    if release or _SO_REUSEPORT is None:
        s.close()
    else:
        _port_reservations.append(s)
    return port


def alloc_endpoint(release=False):
    """Return a (host, port) tuple on loopback with a freshly allocated port."""
    return (LOCALHOST, get_free_port(release=release))


def addr_str(endpoint):
    return "{0}:{1}".format(endpoint[0], endpoint[1])


# ---------------------------------------------------------------------------
# Release binary
# ---------------------------------------------------------------------------

_binary_cache = {}


def _go_cmd():
    return os.environ.get("GHOSTUNNEL_GO", "go")


def build_release_binary():
    """Build (once per process) and return the path to ghostunnel.bench.

    Plain `go build -trimpath` — no coverage instrumentation, which would skew
    timings. Rebuilds on first call so the binary tracks the source tree.
    """
    if "path" in _binary_cache:
        return _binary_cache["path"]
    output = os.path.join(_ROOT_DIR, "ghostunnel.bench")
    if IS_WINDOWS:
        output += ".exe"
    print_ok("building release binary {0}".format(output))
    subprocess.check_call(
        [_go_cmd(), "build", "-trimpath", "-o", output, "."],
        cwd=_ROOT_DIR,
    )
    _binary_cache["path"] = output
    return output


def go_version():
    try:
        out = subprocess.check_output([_go_cmd(), "version"], cwd=_ROOT_DIR)
        return out.decode().strip()
    except Exception:
        return "unknown"


def git_sha():
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=_ROOT_DIR)
        return out.decode().strip()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Certificates (mirrors the tests/common.py RootCert openssl recipe)
# ---------------------------------------------------------------------------

_KEYGEN = {
    "ecdsa":   "openssl ecparam -name prime256v1 -genkey -noout -out {0}",
    "rsa":     "openssl genrsa -out {0} 2048",
    "ed25519": "openssl genpkey -algorithm ed25519 -out {0}",
}

_SAN = "IP:127.0.0.1,IP:::1,DNS:localhost"


@dataclass
class CertSet:
    dir: str
    ca: str
    server_crt: str
    server_key: str
    client_crt: str
    client_key: str
    algorithm: str

    def cleanup(self):
        if self.dir and os.path.isdir(self.dir):
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = None


def _run(cmd, cwd):
    subprocess.check_call(cmd, shell=True, cwd=cwd,
                          stderr=subprocess.DEVNULL)


def gen_certs(algorithm="ecdsa"):
    """Generate CA + server + client PEM certs in a fresh temp dir."""
    if algorithm not in _KEYGEN:
        raise ValueError("unknown algorithm: {0}".format(algorithm))
    if algorithm == "ed25519":
        # Skip cleanly if OpenSSL can't do Ed25519 (matches check_ed25519_support).
        try:
            subprocess.check_call("openssl genpkey -algorithm ed25519 -out " +
                                  os.devnull, shell=True,
                                  stderr=subprocess.DEVNULL)
        except Exception:
            print_err("skipping: OpenSSL does not support ed25519")
            sys.exit(2)

    d = tempfile.mkdtemp(prefix="ghostunnel-bench-certs-")

    def keygen(name):
        _run(_KEYGEN[algorithm].format(name + ".key"), d)

    # CA
    keygen("ca")
    _run('openssl req -x509 -new -key ca.key -days 5 -out ca.crt '
         '-addext "keyUsage = digitalSignature, cRLSign, keyCertSign" '
         '-subj /C=US/ST=CA/O=ghostunnel/OU=root', d)

    # Leaf certs (CN == OU so --allow-ou=client / OU checks work).
    for name in ("server", "client"):
        ext = os.path.join(d, name + ".ext")
        with open(ext, "w") as f:
            f.write("extendedKeyUsage=clientAuth,serverAuth\n")
            f.write("subjectAltName = {0},DNS:{1}\n".format(_SAN, name))
        keygen(name)
        _run("openssl req -new -key {0}.key -out {0}.csr "
             "-subj /CN={0}/C=US/ST=CA/O=ghostunnel/OU={0}".format(name), d)
        _run("openssl x509 -req -in {0}.csr -CA ca.crt -CAkey ca.key "
             "-CAcreateserial -out {0}.crt -days 5 -extfile {0}.ext".format(name), d)

    certs = CertSet(
        dir=d,
        ca=os.path.join(d, "ca.crt"),
        server_crt=os.path.join(d, "server.crt"),
        server_key=os.path.join(d, "server.key"),
        client_crt=os.path.join(d, "client.crt"),
        client_key=os.path.join(d, "client.key"),
        algorithm=algorithm,
    )
    atexit.register(certs.cleanup)
    return certs


# ---------------------------------------------------------------------------
# Status / metrics scraping
# ---------------------------------------------------------------------------

def _no_verify_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _status_url(status_addr, path):
    return "https://{0}:{1}{2}".format(status_addr[0], status_addr[1], path)


def wait_ready(status_addr, timeout=30):
    """Poll the /_status endpoint until ghostunnel is accepting connections."""
    ctx = _no_verify_ctx()
    deadline = time.time() + timeout
    iteration = 0
    last = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(
                _status_url(status_addr, "/_status"), context=ctx, timeout=2).read()
            return
        except Exception as e:
            last = e
        time.sleep(min(0.05 * (2 ** iteration), 1.0))
        iteration += 1
    raise TimeoutError("status {0} not ready after {1}s: {2}".format(
        status_addr, timeout, last))


def scrape_status(status_addr):
    """Return ghostunnel's metrics as {metric_name: value} from /_metrics/json."""
    ctx = _no_verify_ctx()
    raw = urllib.request.urlopen(
        _status_url(status_addr, "/_metrics/json"), context=ctx, timeout=5).read()
    items = json.loads(raw)
    out = {}
    for item in items:
        if isinstance(item, dict) and "metric" in item:
            out[item["metric"]] = item.get("value", item)
    return out


# ---------------------------------------------------------------------------
# Process / topology management
# ---------------------------------------------------------------------------

def _spawn(cmd, name):
    print_ok("starting {0}:\n  {1}".format(name, " ".join(cmd)))
    return subprocess.Popen(cmd)


def _terminate(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        for _ in range(10):
            try:
                proc.wait(timeout=1)
                return
            except Exception:
                pass
        proc.kill()
    except Exception:
        pass


@dataclass
class Topology:
    listen: tuple                       # where the load tool connects
    backend: tuple                      # backend addr (HTTP server or iperf3 -s)
    server_status: tuple = None
    client_status: tuple = None
    _procs: list = field(default_factory=list)

    @property
    def status(self):
        return self.server_status

    def scrape(self, which="server"):
        addr = self.client_status if which == "client" else self.server_status
        return scrape_status(addr)

    def teardown(self):
        # Terminate in reverse start order (load-facing first).
        for proc, _name in reversed(self._procs):
            _terminate(proc)
        self._procs = []


def _gunnel_common(binary):
    # Fast teardown + silence per-connection logging (logging I/O would
    # otherwise show up in the hot path at high connection rates).
    return [binary, "--shutdown-timeout=1s", "--close-timeout=1s", "--quiet=all"]


def _wait_backend_ready(proc, name):
    """Block until the http_backend prints READY (it does so once listening)."""
    line = proc.stdout.readline() if proc.stdout else b""
    if not line:
        raise RuntimeError("{0} failed to start".format(name))


def start_server_topology(certs, *, tls_max=None, max_conns=0, resp_size=64):
    """HTTP backend + one ghostunnel server (mTLS). Load tool -> server -> backend."""
    binary = build_release_binary()
    backend = alloc_endpoint()
    listen = alloc_endpoint()
    status = alloc_endpoint()

    procs = []

    backend_proc = subprocess.Popen(
        [sys.executable, _HTTP_BACKEND, "--host", backend[0],
         "--port", str(backend[1]), "--size", str(resp_size)],
        stdout=subprocess.PIPE)
    procs.append((backend_proc, "http-backend"))
    _wait_backend_ready(backend_proc, "http-backend")

    args = _gunnel_common(binary) + [
        "server",
        "--listen=" + addr_str(listen),
        "--target=" + addr_str(backend),
        "--cert=" + certs.server_crt,
        "--key=" + certs.server_key,
        "--cacert=" + certs.ca,
        "--allow-ou=client",
        "--status=" + addr_str(status),
        "--max-concurrent-conns=" + str(max_conns),
    ]
    if tls_max:
        args.append("--max-tls-version=" + tls_max)
    procs.append((_spawn(args, "ghostunnel-server"), "ghostunnel-server"))

    topo = Topology(listen=listen, backend=backend, server_status=status,
                    _procs=procs)
    try:
        wait_ready(status)
    except Exception:
        topo.teardown()
        raise
    return topo


def start_fullchain_topology(certs, *, tls_max=None):
    """iperf3 -s + ghostunnel server + ghostunnel client. Plain TCP both ends."""
    require_tool("iperf3")
    binary = build_release_binary()

    backend = alloc_endpoint(release=True)   # iperf3 -s (can't set SO_REUSEPORT)
    server_listen = alloc_endpoint()    # ghostunnel server TLS listen
    server_status = alloc_endpoint()
    client_listen = alloc_endpoint()    # ghostunnel client plain listen (iperf3 -c target)
    client_status = alloc_endpoint()

    procs = []

    procs.append((_spawn(
        ["iperf3", "-s", "-B", backend[0], "-p", str(backend[1])],
        "iperf3-server"), "iperf3-server"))
    time.sleep(0.3)  # iperf3 -s has no readiness signal; brief settle

    server_args = _gunnel_common(binary) + [
        "server",
        "--listen=" + addr_str(server_listen),
        "--target=" + addr_str(backend),
        "--cert=" + certs.server_crt,
        "--key=" + certs.server_key,
        "--cacert=" + certs.ca,
        "--allow-ou=client",
        "--status=" + addr_str(server_status),
    ]
    if tls_max:
        server_args.append("--max-tls-version=" + tls_max)
    procs.append((_spawn(server_args, "ghostunnel-server"), "ghostunnel-server"))

    client_args = _gunnel_common(binary) + [
        "client",
        "--listen=" + addr_str(client_listen),
        "--target=" + addr_str(server_listen),
        "--cert=" + certs.client_crt,
        "--key=" + certs.client_key,
        "--cacert=" + certs.ca,
        "--status=" + addr_str(client_status),
    ]
    if tls_max:
        client_args.append("--max-tls-version=" + tls_max)
    procs.append((_spawn(client_args, "ghostunnel-client"), "ghostunnel-client"))

    topo = Topology(listen=client_listen, backend=backend,
                    server_status=server_status, client_status=client_status,
                    _procs=procs)
    try:
        wait_ready(server_status)
        wait_ready(client_status)
    except Exception:
        topo.teardown()
        raise
    return topo


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class Result:
    bench: str
    params: dict
    metric: dict
    raw: dict = None
    git_sha: str = None
    go_version: str = None
    host: str = None
    os: str = None
    timestamp: str = None

    def __post_init__(self):
        self.git_sha = self.git_sha or git_sha()
        self.go_version = self.go_version or go_version()
        self.host = self.host or platform.node()
        self.os = self.os or "{0}/{1}".format(platform.system(), platform.machine())
        self.timestamp = self.timestamp or time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_result(result):
    """Write a result as JSON (timestamped dir) + append a CSV row. Returns JSON path."""
    run_dir = os.path.join(_RESULTS_DIR, result.timestamp.replace(":", ""))
    os.makedirs(run_dir, exist_ok=True)
    json_path = os.path.join(run_dir, result.bench + ".json")
    with open(json_path, "w") as f:
        json.dump(asdict(result), f, indent=2, sort_keys=True)

    csv_path = os.path.join(_RESULTS_DIR, result.bench + ".csv")
    row = {
        "timestamp": result.timestamp,
        "git_sha": result.git_sha,
        "go_version": result.go_version,
        "host": result.host,
        "os": result.os,
        **{"param_" + k: v for k, v in result.params.items()},
        **{"metric_" + k: v for k, v in result.metric.items()},
    }
    write_header = not os.path.exists(csv_path)
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if write_header:
            writer.writeheader()
        writer.writerow(row)

    primary = result.metric.get("primary")
    unit = result.metric.get("unit", "")
    print_ok("{0} {1}: {2} {3}  ({4})".format(
        result.bench, result.params, primary, unit, json_path))
    return json_path
