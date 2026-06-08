#!/usr/bin/env python3
"""
Integration test for ACME TLS-ALPN-01 renewal under mTLS.

Bug: ghostunnel's mTLS default sets ClientAuth=RequireAndVerifyClientCert
on the main listener. The TLS-ALPN-01 renewal probe sends no client cert,
so before the fix the renewal handshake aborted and the cert silently
expired.

To make the renewal path observable in a test we force the timing:

  * Pebble issues certs with a 30-second validity period.
  * Ghostunnel runs with --auto-acme-renew-check-interval=1s (hidden flag,
    test-only), so certmagic's background maintenance loop wakes up every
    second instead of every 10 minutes.

certmagic computes "needs renewal" against RenewalWindowRatio (default
1/3), so for a 30-second cert it tries to renew once roughly 10 seconds
remain. That renewal happens while ghostunnel's main listener already owns
port 443; certmagic's solver can't bind it (robustTryListen falls through
with nil/nil), stashes the challenge cert in its in-memory map, and trusts
the existing listener to serve it. Without the fix, ghostunnel's mTLS
config rejects Pebble's no-cert probe and renewal fails. With the fix,
the probe handshake completes, GetCertificate serves the challenge cert,
Pebble validates, and a new cert is issued.

The test asserts:
  1. Ghostunnel obtains the initial cert (initial issuance via certmagic's
     own internal listener — does NOT exercise the fix).
  2. Ghostunnel performs a successful renewal while serving the main
     listener — the cert's NotBefore advances. This DOES exercise the fix.
  3. A real mTLS client (no acme-tls/1 ALPN, valid client cert) is still
     proxied normally throughout.

Skips if pebble is not on PATH or if the test process can't bind port 443
(needs root or CAP_NET_BIND_SERVICE on the ghostunnel binary).
"""

import hashlib
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time

from common import (
    LOCALHOST,
    RootCert,
    get_free_port,
    print_ok,
    require_can_bind_privileged_port,
    require_platform,
    require_pebble,
    run_ghostunnel,
    start_pebble,
    terminate,
    terminate_pebble,
    TARGET_PORT,
)


def wait_for_ghostunnel_listener(port, client_cert, timeout=60):
    """Poll until a valid mTLS handshake to (LOCALHOST, port) succeeds.

    A bare TCP accept isn't enough: during initial issuance certmagic
    binds the same port for its TLS-ALPN-01 challenge listener and then
    releases it just before ghostunnel binds. A TCP-only probe can race
    that handoff and "succeed" against certmagic's listener while
    ghostunnel hasn't bound yet. By driving a real mTLS handshake with a
    valid client cert and no ALPN, we accept only ghostunnel's main
    listener: certmagic's challenge listener has no cert to serve for a
    no-ALPN ClientHello (its GetCertificate only fires for acme-tls/1).
    """
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        ok, _, conn_or_err = tls_probe(port, alpn=None, client_cert=client_cert)
        if ok:
            try:
                conn_or_err.close()
            except OSError:
                # Cleanup only; nothing actionable if close fails here.
                pass
            return
        last_err = conn_or_err
        time.sleep(0.5)
    raise TimeoutError(
        "ghostunnel listener on port {0} not ready in {1}s "
        "(last handshake error: {2})".format(port, timeout, last_err))

FQDN = 'localhost'  # Pebble validates against the SNI/identifier; localhost
                    # resolves on every test platform.

# certmagic's internal TLS-ALPN-01 listener defaults to port 443
# (ACMEIssuer.AltTLSALPNPort=0). For initial issuance to succeed, Pebble must
# dial 443 *and* certmagic must be allowed to bind it. After issuance,
# ghostunnel itself binds 443 for the main listener, where the renewal probe
# shape is exercised. The bind requires either root or CAP_NET_BIND_SERVICE
# on the ghostunnel binary; require_can_bind_privileged_port gates on that.
ACME_PORT = 443

# Force a fast renewal cycle. Pebble issues 30-second certs; certmagic's
# renewal threshold (RenewalWindowRatio=1/3) fires when ~10s remain, i.e.
# ~20s after issuance. We poll certmagic with a 1-second check interval
# (hidden flag --auto-acme-renew-check-interval).
CERT_VALIDITY_SECONDS = 30
RENEW_CHECK_INTERVAL = '1s'
RENEWAL_DEADLINE_SECONDS = 45


class BackendListener:
    """A target listener that records whether anything ever connected.

    Used to assert that ACME probe traffic never reaches the backend.
    """

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((LOCALHOST, port))
        self.sock.listen(8)
        self.accepted = 0
        self.received = b''
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self.sock.settimeout(0.25)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            try:
                conn.settimeout(2)
                chunk = conn.recv(4096)
                if chunk:
                    self.received += chunk
                    conn.sendall(chunk)  # echo for scenario 4
            except OSError:
                # Per-client I/O errors must not kill the listener thread.
                pass
            finally:
                conn.close()

    def reset_counters(self):
        self.accepted = 0
        self.received = b''

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            # Best-effort teardown; nothing to do if the socket was already closed.
            pass
        self._thread.join(timeout=2)


def tls_probe(server_port, alpn=None, client_cert=None):
    """Open a TLS connection to the proxy.

    alpn        : list of ALPN protocols to advertise, or None to omit the
                  extension entirely
    client_cert : base name of a cert pair ({name}.crt + {name}.key), or
                  None for no client certificate

    Returns (handshake_ok, negotiated_alpn_or_None, ssock_or_error_str).
    On success the caller owns the returned SSLSocket and must close it.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Pin TLS 1.2 only. The test asserts handshake outcomes (e.g. "no-cert
    # client rejected"); in TLS 1.3 the client returns from wrap_socket
    # before the server's CertificateRequired alert arrives, so a
    # server-side rejection wouldn't surface until first I/O. Forcing 1.2
    # makes the handshake fully synchronous, so wrap_socket raises iff the
    # server rejected. (Silences a CodeQL alert as a bonus.)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if client_cert is not None:
        ctx.load_cert_chain(certfile=client_cert + '.crt',
                            keyfile=client_cert + '.key')
    try:
        sock = socket.create_connection((LOCALHOST, server_port), timeout=5)
    except OSError as e:
        # No listener yet (or it just closed). Treat as a failed probe.
        return False, None, str(e)
    try:
        wrapped = ctx.wrap_socket(sock, server_hostname=FQDN)
    except (ssl.SSLError, OSError) as e:
        try:
            sock.close()
        except OSError:
            # Socket may already be half-closed by the failing handshake;
            # any close error is uninteresting because we're returning the
            # original handshake error to the caller.
            pass
        return False, None, str(e)
    return True, wrapped.selected_alpn_protocol(), wrapped


def fetch_server_cert_fingerprint(port, client_cert):
    """Open a valid mTLS connection and return sha256(server_cert_der) hex.

    Used to detect cert rotation across a renewal — the server's leaf cert
    only changes when certmagic obtains a new one. The client cert is
    required because the listener enforces mTLS; without one we can't
    complete the handshake and thus can't read the peer cert from Python.
    """
    ok, _, conn = tls_probe(port, alpn=None, client_cert=client_cert)
    if not ok:
        raise RuntimeError("could not fetch server cert: {0}".format(conn))
    try:
        der = conn.getpeercert(binary_form=True)
    finally:
        try:
            conn.close()
        except OSError:
            # Already torn down by either side; nothing to report.
            pass
    return hashlib.sha256(der).hexdigest()


pebble = None
ghostunnel = None
backend = None
work_dir = tempfile.mkdtemp(prefix='ghostunnel-acme-test-')

try:
    # This test relies on a long-running TLS listener for Pebble to dial
    # into for TLS-ALPN-01 validation. The mechanics work on Linux/macOS;
    # skip Windows because Pebble's Windows story is poorly tested.
    require_platform('Linux', 'Darwin')
    require_pebble()
    # Port 443 is privileged: either we're root, or the ghostunnel binary has
    # CAP_NET_BIND_SERVICE.
    require_can_bind_privileged_port()

    pebble_directory_port = get_free_port()
    pebble_mgmt_port = get_free_port()

    # Issue the test client cert from a separate root — this verifies that
    # the ACME-issued server cert and the mTLS client cert come from
    # *different* trust paths, which is the realistic deployment shape.
    client_root = RootCert('client-root')
    client_root.create_signed_cert('client')

    # Start Pebble; it will dial back to ACME_PORT (443) to run TLS-ALPN-01
    # validation. Issue short-lived certs so certmagic decides to renew
    # within seconds.
    pebble, directory_url, pebble_ca = start_pebble(
        work_dir, pebble_directory_port, pebble_mgmt_port, ACME_PORT,
        cert_validity_seconds=CERT_VALIDITY_SECONDS)
    print_ok("pebble running at {0} (cert validity={1}s)".format(
        directory_url, CERT_VALIDITY_SECONDS))

    backend = BackendListener(TARGET_PORT)

    # Start ghostunnel in ACME mode with mTLS enforced via --allow-cn.
    # SSL_CERT_FILE makes Go trust Pebble's self-signed directory cert.
    # XDG_DATA_HOME isolates certmagic's cert cache into the test work dir,
    # so repeated runs don't pick up stale state from a prior CA.
    certmagic_home = os.path.join(work_dir, 'certmagic')
    os.makedirs(certmagic_home, exist_ok=True)
    os.environ['SSL_CERT_FILE'] = pebble_ca
    os.environ['XDG_DATA_HOME'] = certmagic_home

    ghostunnel = run_ghostunnel([
        'server',
        '--listen={0}:{1}'.format(LOCALHOST, ACME_PORT),
        '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
        '--auto-acme-cert={0}'.format(FQDN),
        '--auto-acme-email=test@example.com',
        '--auto-acme-agree-to-tos',
        '--auto-acme-ca={0}'.format(directory_url),
        '--auto-acme-renew-check-interval={0}'.format(RENEW_CHECK_INTERVAL),
        '--cacert={0}.crt'.format(client_root.name),
        '--allow-cn=client',
    ])

    # Wait for ghostunnel's main listener to come up. We probe with a real
    # mTLS handshake so we don't race certmagic's brief challenge-listener
    # window during initial issuance.
    wait_for_ghostunnel_listener(ACME_PORT, 'client', timeout=60)
    print_ok("ghostunnel obtained initial ACME certificate and is listening")

    # The readiness probe itself dialed the backend (real mTLS connection
    # got proxied through). Give the backend's accept loop a moment to
    # observe the close, then we can reset counters cleanly.
    time.sleep(0.5)

    # -----------------------------------------------------------------
    # Pre-renewal sanity: mTLS works for valid client, rejects no-cert.
    # We omit ALPN to avoid colliding with NextProtos=["acme-tls/1"];
    # without ALPN the handshake reaches the cert exchange and mTLS
    # gates there.
    # -----------------------------------------------------------------
    backend.reset_counters()
    ok, _, err = tls_probe(ACME_PORT, alpn=None)
    assert not ok, "no-cert client must be rejected at handshake"
    time.sleep(0.2)
    assert backend.accepted == 0, "no-cert handshake must not reach backend"

    backend.reset_counters()
    ok, _, conn = tls_probe(ACME_PORT, alpn=None, client_cert='client')
    assert ok, "valid mTLS client handshake must succeed: {0}".format(conn)
    try:
        conn.sendall(b'pre-renewal-ping')
        echoed = conn.recv(4096)
    finally:
        conn.close()
    time.sleep(0.2)
    assert backend.accepted >= 1, "valid mTLS client must reach backend"
    assert echoed.startswith(b'pre-renewal-ping'), (
        "expected backend echo, got {0!r}".format(echoed))
    print_ok("pre-renewal mTLS sanity PASS")

    initial_fpr = fetch_server_cert_fingerprint(ACME_PORT, 'client')
    print_ok("initial server cert sha256={0}...".format(initial_fpr[:16]))

    # -----------------------------------------------------------------
    # The bug under test: renewal under mTLS.
    #
    # certmagic's background loop will wake up (every 1s thanks to the
    # hidden flag), notice the cert is past its renewal threshold, and
    # initiate a new ACME order. Because ghostunnel already owns port
    # 443, certmagic's solver can't bind it; robustTryListen falls
    # through with (nil, nil), stashes the challenge cert in
    # activeChallenges, and trusts the existing listener to serve it.
    #
    # That existing listener is ghostunnel's main one, configured with
    # ClientAuth=RequireAndVerifyClientCert. The fix is a
    # GetConfigForClient callback that relaxes ClientAuth for an
    # acme-tls/1 ClientHello. Without the fix, Pebble's probe is
    # rejected at the handshake's CertificateRequest step and renewal
    # silently fails — the test will then time out with the cert never
    # rotating.
    # -----------------------------------------------------------------
    print_ok("waiting up to {0}s for cert rotation...".format(
        RENEWAL_DEADLINE_SECONDS))
    deadline = time.time() + RENEWAL_DEADLINE_SECONDS
    rotated_fpr = initial_fpr
    while time.time() < deadline:
        time.sleep(2)
        try:
            rotated_fpr = fetch_server_cert_fingerprint(ACME_PORT, 'client')
        except (RuntimeError, OSError):
            # Listener may be momentarily unstable during the renewal.
            continue
        if rotated_fpr != initial_fpr:
            break

    assert rotated_fpr != initial_fpr, (
        "BUG: server certificate did not rotate within {0}s — "
        "TLS-ALPN-01 renewal under mTLS failed silently".format(
            RENEWAL_DEADLINE_SECONDS))
    print_ok("renewal-under-mTLS PASS: cert rotated to sha256={0}...".format(
        rotated_fpr[:16]))

    # -----------------------------------------------------------------
    # Post-renewal sanity: mTLS still works after the renewal completes.
    # -----------------------------------------------------------------
    backend.reset_counters()
    ok, _, conn = tls_probe(ACME_PORT, alpn=None, client_cert='client')
    assert ok, "post-renewal mTLS handshake must succeed: {0}".format(conn)
    try:
        conn.sendall(b'post-renewal-ping')
        echoed = conn.recv(4096)
    finally:
        conn.close()
    assert echoed.startswith(b'post-renewal-ping'), (
        "expected backend echo post-renewal, got {0!r}".format(echoed))
    print_ok("post-renewal mTLS sanity PASS")

finally:
    terminate(ghostunnel)
    terminate_pebble(pebble)
    if backend is not None:
        backend.close()
    shutil.rmtree(work_dir, ignore_errors=True)
