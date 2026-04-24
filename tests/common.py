from subprocess import call, check_call, check_output, Popen, DEVNULL
from tempfile import mkstemp, mkdtemp
import atexit
import json
import shutil
import sys
import time
import socket
import ssl
import os
import platform
import struct
import urllib.error
import urllib.request

LOCALHOST = '127.0.0.1'
IS_WINDOWS = platform.system() == 'Windows'
TIMEOUT = int(os.environ.get('GHOSTUNNEL_TEST_TIMEOUT', '10'))


def parse_tlvs(data):
    """Parse a PROXY protocol v2 TLV vector from raw bytes.

    Returns a list of (type, value) tuples."""
    tlvs = []
    i = 0
    while i < len(data):
        if i + 3 > len(data):
            raise Exception("truncated TLV at offset {0}".format(i))
        tlv_type = data[i]
        tlv_len = struct.unpack('!H', data[i+1:i+3])[0]
        i += 3
        if i + tlv_len > len(data):
            raise Exception("truncated TLV value at offset {0}".format(i))
        tlv_value = data[i:i+tlv_len]
        i += tlv_len
        tlvs.append((tlv_type, tlv_value))
    return tlvs


def _poll_sleep(iteration):
    """Exponential backoff: 0.05, 0.1, 0.2, 0.4, 0.8, 1.0, 1.0, ..."""
    time.sleep(min(0.05 * (2 ** iteration), 1.0))

# Store original directory paths before changing working directory
_TESTS_DIR = os.path.abspath(os.path.dirname(__file__) or '.')
_ROOT_DIR = os.path.abspath(os.path.join(_TESTS_DIR, '..'))
_GHOSTUNNEL_BINARY = os.path.join(_ROOT_DIR, 'ghostunnel.test.exe' if IS_WINDOWS else 'ghostunnel.test')
_COVERAGE_DIR = os.path.join(_ROOT_DIR, 'coverage')
os.makedirs(_COVERAGE_DIR, exist_ok=True)

_SO_REUSEPORT = getattr(socket, 'SO_REUSEPORT', None)

# Holds reservation sockets for ports allocated by get_free_port()
_extra_port_sockets = []
atexit.register(lambda: [s.close() for s in _extra_port_sockets])


def get_free_port(release=False):
    """Get an available port by binding to port 0.

    On platforms with SO_REUSEPORT, the reservation socket is kept open for
    the lifetime of the process to prevent other parallel test processes from
    being assigned the same port.  Pass release=True to close the socket
    immediately — use this when the caller will bind the port exclusively
    right away (e.g. port-conflict tests).

    On Windows (no SO_REUSEPORT), the socket is always closed immediately
    since co-binding is not possible."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if _SO_REUSEPORT is not None:
        s.setsockopt(socket.SOL_SOCKET, _SO_REUSEPORT, 1)
    s.bind((LOCALHOST, 0))
    port = s.getsockname()[1]
    if release or _SO_REUSEPORT is None:
        s.close()
    else:
        _extra_port_sockets.append(s)
    return port


# Allocate unique ports per test process at import time.
# Reservation sockets stay open for the lifetime of the process.
# Ghostunnel can co-bind because it also uses SO_REUSEPORT.
STATUS_PORT = get_free_port()
LISTEN_PORT = get_free_port()
TARGET_PORT = get_free_port()

# Create a per-test temporary working directory for cert file isolation
_WORK_DIR = mkdtemp(prefix='ghostunnel-test-')
os.chdir(_WORK_DIR)


def _cleanup_work_dir():
    """Clean up the temporary working directory on exit."""
    try:
        os.chdir(_TESTS_DIR)
        shutil.rmtree(_WORK_DIR, ignore_errors=True)
    except Exception:
        pass  # best-effort cleanup, may fail during interpreter shutdown


atexit.register(_cleanup_work_dir)


def run_ghostunnel(args, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, prefix=None):
    """Helper to run ghostunnel in integration test mode"""

    # Set lower than default timeouts to speed up tests
    if not any('shutdown-timeout' in f for f in args):
        args.append('--shutdown-timeout=1s')
    if not any('close-timeout' in f for f in args):
        args.append('--close-timeout=1s')

    # Pass args through env var into integration test hook
    env = os.environ.copy()
    env["SYSTEMD_LOG_TARGET"] = "console"
    env["SYSTEMD_LOG_LEVEL"] = "debug"
    env["GHOSTUNNEL_INTEGRATION_TEST"] = "true"
    env["GHOSTUNNEL_INTEGRATION_ARGS"] = json.dumps(args)

    # Run it, hook up stdout/stderr if desired
    test = os.path.basename(sys.argv[0]).replace('.py', '.profile')
    cmd = [
        _GHOSTUNNEL_BINARY,
        '-test.run=TestIntegrationMain',
        '-test.coverprofile={0}/{1}'.format(_COVERAGE_DIR, test)
    ]

    if prefix:
        cmd = prefix + cmd

    # Print cmd for debugging
    print_ok("running:\n {0}\nwith args:\n {1}".format(' \\\n  '.join(cmd), ' \\\n  '.join(args)))

    return Popen(cmd, stdout=stdout, stderr=stderr, env=env)

def assert_not_zero(ghostunnel):
    ret = ghostunnel.wait(timeout=5)
    if ret == 0:
        raise Exception(
            'ghostunnel terminated with zero, but expected otherwise')
    print_ok("OK (terminated)")

def terminate(ghostunnel):
    """Gracefully terminate ghostunnel (with timeout)"""
    print_ok("terminating ghostunnel instance")
    try:
        if ghostunnel:
            ghostunnel.terminate()
            for i in range(10):
                try:
                    ghostunnel.wait(timeout=1)
                except Exception:
                    pass  # wait() may raise if process hasn't exited yet
                if ghostunnel.returncode is not None:
                    print_ok("ghostunnel stopped with exit code {0}".format(
                        ghostunnel.returncode))
                    return
                _poll_sleep(i)
            print_ok("timeout, killing ghostunnel")
            ghostunnel.kill()
    except Exception:
        pass  # best-effort termination, ignore errors during cleanup

def status_info():
    """Fetch info from status port"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        return json.loads(urllib.request.urlopen(
            "https://{0}:{1}/_status".format(
                LOCALHOST, STATUS_PORT),
            context=ctx).read())
    except urllib.error.HTTPError as e:
        # Ignore 503 if it occurs
        # We just want the JSON in the response for testing
        return json.loads(e.read().decode())
    except Exception as e:
        print('unable to fetch status:', e)
        return None

def wait_for_status(predicate, timeout=30):
    """Poll status_info() until predicate(info) is truthy, with timeout."""
    deadline = time.time() + timeout
    iteration = 0
    while time.time() < deadline:
        info = status_info()
        if info and predicate(info):
            return info
        _poll_sleep(iteration)
        iteration += 1
    raise TimeoutError("status check timed out after {0}s".format(timeout))

def dump_goroutines():
    """Attempt to dump goroutines via status port/pprof"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sys.stderr.buffer.write(urllib.request.urlopen(
            "https://{0}:{1}/debug/pprof/goroutine?debug=1".format(
                LOCALHOST, STATUS_PORT),
            context=ctx).read())
    except Exception as e:
        print('unable to dump goroutines:', e)

class RootCert:
    """Helper class to create root + signed certs"""
    _KEYGEN = {
        'ecdsa':   'openssl ecparam -name prime256v1 -genkey -noout -out {0}.key',
        'rsa':     'openssl genrsa -out {0}.key 2048',
        'ed25519': 'openssl genpkey -algorithm ed25519 -out {0}.key',
    }

    def __init__(self, name, algorithm='ecdsa'):
        self.name = name
        self.algorithm = algorithm
        self.leaf_certs = []
        print_ok("generating {0}.key, {0}.crt".format(name))
        check_call(
            self._KEYGEN[algorithm].format(name),
            shell=True,
            stderr=DEVNULL)
        check_call(
            'openssl req -x509 -new -key {0}.key -days 5 -out {0}_temp.crt -addext "keyUsage = digitalSignature, cRLSign, keyCertSign" -subj /C=US/ST=CA/O=ghostunnel/OU={0}'.format(name),
            shell=True)
        os.replace("{0}_temp.crt".format(name), "{0}.crt".format(name))

    def create_signed_cert(self, cn_and_ou, san="IP:127.0.0.1,IP:::1,DNS:localhost", p12_password=''):
        if p12_password is not None:
            print_ok("generating {0}.key, {0}.crt, {0}.p12".format(cn_and_ou))
        else:
            print_ok("generating {0}.key, {0}.crt".format(cn_and_ou))
        fd, openssl_config = mkstemp(dir='.')
        os.write(fd, b"extendedKeyUsage=clientAuth,serverAuth\n")
        os.write(fd, "subjectAltName = {0},DNS:{1}".format(san, cn_and_ou).encode('utf-8'))
        check_call(self._KEYGEN[self.algorithm].format(cn_and_ou),
             shell=True, stderr=DEVNULL)
        check_call(
            "openssl req -new -key {0}.key -out {0}.csr -subj /CN={0}/C=US/ST=CA/O=ghostunnel/OU={0}".format(cn_and_ou),
            shell=True,
            stderr=DEVNULL)
        check_call(
            "openssl x509 -req -in {0}.csr -CA {1}.crt -CAkey {1}.key -CAcreateserial -out {0}_temp.crt -days 5 -extfile {2}".format(
                cn_and_ou,
                self.name,
                openssl_config),
            shell=True,
            stderr=DEVNULL)
        os.replace("{0}_temp.crt".format(cn_and_ou), "{0}.crt".format(cn_and_ou))
        if p12_password is not None:
            check_call(
                "openssl pkcs12 -export -out {0}_temp.p12 -in {0}.crt -inkey {0}.key -password pass:{1}".format(cn_and_ou, p12_password),
                shell=True)
            os.replace("{0}_temp.p12".format(cn_and_ou), "{0}.p12".format(cn_and_ou))
        os.close(fd)
        os.remove(openssl_config)
        self.leaf_certs.append(cn_and_ou)

    def cleanup(self):
        """Explicitly clean up all cert files created by this RootCert."""
        RootCert.cleanup_certs([self.name])
        RootCert.cleanup_certs(self.leaf_certs)
        self.name = None
        self.leaf_certs = []

    def __del__(self):
        if self.name is not None:
            self.cleanup()

    @staticmethod
    def cleanup_certs(names):
        for name in names:
            for ext in ["crt", "key", "csr", "srl", "p12", "jceks"]:
                try:
                    os.remove('{0}.{1}'.format(name, ext))
                except OSError:
                    pass  # file may not exist

def assert_connection_rejected(client, server, name, timeout_ok=True, timeout=2):
    """Assert that a SocketPair connection is rejected.

    By default accepts both ssl.SSLError and TimeoutError (appropriate for
    server-side rejection tests). Pass timeout_ok=False to only accept
    ssl.SSLError — use this for client-side tests where ghostunnel performs
    the TLS verification and should fail the handshake immediately.

    When timeout_ok is True, a short timeout (default 2s, capped at TIMEOUT)
    is used on the backend accept to avoid waiting the full TIMEOUT (10s) for
    connections that will never be forwarded."""
    try:
        SocketPair(client, server, timeout=min(timeout, TIMEOUT) if timeout_ok else None)
        raise Exception('failed to reject {0}'.format(name))
    except ssl.SSLError:
        print_ok("{0} correctly rejected".format(name))
    except TimeoutError as exc:
        if timeout_ok:
            print_ok("{0} correctly rejected".format(name))
        else:
            raise Exception('expected ssl.SSLError rejecting {0}, got TimeoutError'.format(name)) from exc


def create_default_certs(algorithm='ecdsa'):
    """Create standard root, server, and client certificates.

    Returns the RootCert object. Callers should call root.cleanup()
    in their finally block to clean up temporary cert files."""
    root = RootCert('root', algorithm=algorithm)
    root.create_signed_cert('server')
    root.create_signed_cert('client')
    return root


def start_ghostunnel_server(extra_args=None, keystore='server.p12',
                            cacert='root.crt', allow_ou='client', **kwargs):
    """Start ghostunnel in server mode with standard listen/target/status args.

    Pass allow_ou=None to omit --allow-ou (e.g. for --disable-authentication tests)."""
    args = ['server',
            '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
            '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
            '--keystore={0}'.format(keystore),
            '--cacert={0}'.format(cacert),
            '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)]
    if allow_ou is not None:
        args.append('--allow-ou={0}'.format(allow_ou))
    if extra_args:
        args.extend(extra_args)
    return run_ghostunnel(args, **kwargs)


def start_ghostunnel_client(extra_args=None, keystore='client.p12',
                            cacert='root.crt', **kwargs):
    """Start ghostunnel in client mode with standard listen/target/status args."""
    args = ['client',
            '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
            '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
            '--keystore={0}'.format(keystore),
            '--cacert={0}'.format(cacert),
            '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)]
    if extra_args:
        args.extend(extra_args)
    return run_ghostunnel(args, **kwargs)


EXPECTED_SERVER_METRICS = [
    "ghostunnel.accept.total",
    "ghostunnel.accept.success",
    "ghostunnel.accept.timeout",
    "ghostunnel.accept.error",
    "ghostunnel.conn.open",
    "ghostunnel.conn.lifetime.count",
    "ghostunnel.conn.lifetime.min",
    "ghostunnel.conn.lifetime.max",
    "ghostunnel.conn.lifetime.mean",
    "ghostunnel.conn.lifetime.50-percentile",
    "ghostunnel.conn.lifetime.75-percentile",
    "ghostunnel.conn.lifetime.95-percentile",
    "ghostunnel.conn.lifetime.99-percentile",
    "ghostunnel.conn.handshake.count",
    "ghostunnel.conn.handshake.min",
    "ghostunnel.conn.handshake.max",
    "ghostunnel.conn.handshake.mean",
    "ghostunnel.conn.handshake.50-percentile",
    "ghostunnel.conn.handshake.75-percentile",
    "ghostunnel.conn.handshake.95-percentile",
    "ghostunnel.conn.handshake.99-percentile",
]


def check_ed25519_support():
    """Skip the test if OpenSSL does not support ED25519."""
    devnull = 'NUL' if IS_WINDOWS else '/dev/null'
    try:
        check_output('openssl genpkey -algorithm ed25519 -out {0}'.format(devnull),
                     shell=True, stderr=DEVNULL)
    except Exception:
        print("OpenSSL does not support ED25519", file=sys.stderr)
        sys.exit(2)

def check_keytool():
    """Skip the test if keytool is not available."""
    if not shutil.which('keytool'):
        print("keytool not available", file=sys.stderr)
        sys.exit(2)

def require_platform(*platforms):
    """Skip the test unless running on one of the specified platforms.

    Platform names match platform.system() output: 'Darwin', 'Linux', 'Windows'.
    The special name 'BSD' matches any platform ending in 'BSD'
    (e.g. FreeBSD, OpenBSD, NetBSD).
    """
    current = platform.system()
    if current in platforms:
        return
    if 'BSD' in platforms and current.endswith('BSD'):
        return
    print("skipped: requires {0} (running on {1})".format(
        '/'.join(platforms), current), file=sys.stderr)
    sys.exit(2)

def require_admin():
    """Skip the test (exit 2) unless running with Administrator privileges (Windows)."""
    if not IS_WINDOWS:
        return
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("requires Administrator privileges, skipping", file=sys.stderr)
        sys.exit(2)

def reload_args():
    """Extra args to enable certificate reload on Windows via --timed-reload."""
    return ['--timed-reload=1s'] if IS_WINDOWS else []

def trigger_reload(ghostunnel):
    """Trigger a certificate/config reload.

    On Unix, sends SIGUSR1 to the process.
    On Windows, waits until the timed-reload cycle is observed via the
    status endpoint (requires --timed-reload=1s)."""
    if IS_WINDOWS:
        pre = status_info()
        pre_reload = pre.get('last_reload') if pre else None
        wait_for_status(
            lambda info: info.get('last_reload') != pre_reload, timeout=10)
    else:
        import signal as _signal
        ghostunnel.send_signal(_signal.SIGUSR1)

def convert_p12_to_jceks(p12_name, jceks_name, password):
    """Convert a PKCS#12 keystore to JCEKS format using keytool.
    Skips the test (sys.exit(2)) if the conversion fails."""
    try:
        os.remove('{0}.jceks'.format(jceks_name))
    except OSError:
        pass  # file may not exist from a previous run
    ret = call('keytool -importkeystore '
               '-srckeystore {0}.p12 -srcstoretype PKCS12 -srcstorepass {2} '
               '-destkeystore {1}.jceks -deststoretype JCEKS -deststorepass {2} '
               '-noprompt'.format(p12_name, jceks_name, password),
               shell=True, stderr=DEVNULL)
    if ret != 0:
        print("keytool -importkeystore failed", file=sys.stderr)
        sys.exit(2)

def print_ok(msg):
    print("\033[92m{0}\033[0m".format(msg))

def wrap_socket(socket, keyfile=None, certfile=None, ca_certs=None, cert_reqs=ssl.CERT_REQUIRED, server_side=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if certfile is not None and keyfile is not None:
        ctx.load_cert_chain(certfile, keyfile)
    if ca_certs is not None:
        ctx.load_verify_locations(cafile=ca_certs)
    ctx.verify_mode = cert_reqs
    return ctx.wrap_socket(socket, server_side=server_side)

def urlopen(path):
    context = ssl.create_default_context(cafile='root.crt')
    return urllib.request.urlopen(path, context=context)


def _get_ou(peercert):
    """Extract organizationalUnitName from a peer certificate subject."""
    for rdn in peercert.get('subject', ()):
        for attr_type, attr_value in rdn:
            if attr_type == 'organizationalUnitName':
                return attr_value
    return None

######################### Abstract #########################


class MySocket:
    def __init__(self):
        self.socket = None

    def get_socket(self):
        return self.socket

    def cleanup(self):
        if self.socket:
            self.socket.close()
        self.socket = None

######################### TCP #########################


class TcpClient(MySocket):
    def __init__(self, port):
        super().__init__()
        self.port = port

    def connect(self, attempts=1, msg=''):
        for i in range(attempts):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(TIMEOUT)
                self.socket.connect((LOCALHOST, self.port))
                print_ok(msg)
                return
            except Exception as e:
                print(e)
            print(
                "failed to connect to {0}. Trying again...".format(self.port))
            _poll_sleep(i)

        raise Exception("Failed to connect to {0}".format(self.port))


class TcpServer(MySocket):
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.listener = None

    def listen(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.settimeout(TIMEOUT)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if _SO_REUSEPORT is not None:
            self.listener.setsockopt(socket.SOL_SOCKET, _SO_REUSEPORT, 1)
        self.listener.bind((LOCALHOST, self.port))
        self.listener.listen(1)

    def accept(self):
        self.socket, _ = self.listener.accept()
        self.socket.settimeout(TIMEOUT)
        self.listener.close()
        self.listener = None

    def cleanup(self):
        super().cleanup()
        if self.listener:
            self.listener.close()
        self.listener = None

######################### TLS #########################


class TlsClient(MySocket):
    def __init__(self, cert, ca, port, min_version=None, max_version=None):
        super().__init__()
        self.cert = cert
        self.ca = ca
        self.port = port
        self.min_version = min_version
        self.max_version = max_version

    def connect(self, attempts=1, peer=None):
        for i in range(attempts):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.verify_mode = ssl.CERT_REQUIRED
                if self.ca:
                    ctx.load_verify_locations(cafile=self.ca + '.crt')
                if self.cert:
                    ctx.load_cert_chain(self.cert + '.crt', self.cert + '.key')
                ctx.minimum_version = self.min_version if self.min_version is not None else ssl.TLSVersion.TLSv1_2
                if self.max_version is not None:
                    ctx.maximum_version = self.max_version

                # First create TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                self.socket = ctx.wrap_socket(sock, server_hostname=peer if peer else LOCALHOST)
                self.socket.connect((LOCALHOST, self.port))
                return
            except Exception as e:
                print('connection attempt {0} failed, error: {1}'.format(i, e))
                _poll_sleep(i)

        raise Exception("connection failed after {0} attempts".format(attempts))


class TlsServer(MySocket):
    def __init__(
            self,
            cert,
            ca,
            port,
            cert_reqs=ssl.CERT_REQUIRED):
        super().__init__()
        self.cert = cert
        self.ca = ca
        self.port = port
        self.cert_reqs = cert_reqs
        self.tls_listener = None

    def listen(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(TIMEOUT)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if _SO_REUSEPORT is not None:
            listener.setsockopt(socket.SOL_SOCKET, _SO_REUSEPORT, 1)
        listener.bind((LOCALHOST, self.port))
        listener.listen(1)
        self.tls_listener = wrap_socket(listener,
                                            server_side=True,
                                            keyfile='{0}.key'.format(
                                                self.cert),
                                            certfile='{0}.crt'.format(
                                                self.cert),
                                            ca_certs='{0}.crt'.format(self.ca),
                                            cert_reqs=self.cert_reqs)

    def accept(self):
        self.socket, _ = self.tls_listener.accept()
        self.socket.settimeout(TIMEOUT)
        self.tls_listener.close()
        self.tls_listener = None

    def validate_client_cert(self, ou):
        actual = _get_ou(self.socket.getpeercert())
        if actual == ou:
            return
        raise Exception("did not connect to expected peer: got {}, wanted: {}".format(
                        actual, ou))

    def cleanup(self):
        super().cleanup()
        if self.tls_listener:
            self.tls_listener.close()
        self.tls_listener = None

######################### UNIX SOCKET #########################


class UnixClient(MySocket):
    def __init__(self):
        super().__init__()
        self.socket_path = os.path.join(mkdtemp(), 'ghostunnel-test-socket')

    def get_socket_path(self):
        return self.socket_path

    def connect(self, attempts=1, msg=''):
        for i in range(attempts):
            try:
                self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.socket.settimeout(TIMEOUT)
                self.socket.connect(self.socket_path)
                print_ok(msg)
                return
            except Exception as e:
                print(e)
            print("failed to connect to {0}. Trying again...".format(
                self.socket_path))
            _poll_sleep(i)

        raise Exception("Failed to connect to {0}".format(self.socket_path))

    def cleanup(self):
        super().cleanup()
        os.remove(self.socket_path)
        os.rmdir(os.path.dirname(self.socket_path))


class UnixServer(MySocket):
    def __init__(self):
        super().__init__()
        self.socket_path = os.path.join(mkdtemp(), 'ghostunnel-test-socket')
        self.listening = False
        self.listener = None

    def get_socket_path(self):
        return self.socket_path

    def listen(self):
        if self.listening:
            return
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.settimeout(TIMEOUT)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(self.socket_path)
        self.listener.listen(1)
        self.listening = True

    def accept(self):
        self.socket, _ = self.listener.accept()
        self.socket.settimeout(TIMEOUT)

    def cleanup(self):
        super().cleanup()
        if self.listener:
            self.listener.close()
        self.listener = None
        os.remove(self.socket_path)

######################### SocketPair #########################

# This is whacky but works. This class represents a pair of sockets which
# correspond to each end of the tunnel. The class lets you verify that sending
# data in one socket shows up on the other. It also allows testing that closing
# one socket closes the other.


class SocketPair:
    def __init__(self, client, server, timeout=None):
        self.client = client
        self.server = server
        self.timeout = timeout
        self.client_sock = None
        self.server_sock = None
        self.connect()

    def cleanup(self):
        self.client.cleanup()
        self.server.cleanup()

    def connect(self):
        # calling accept() on a socket blocks until a connection arrives. Ghostunnel
        # doesn't create the backend connection until a connection arrives. This
        # implies we either need to create threads or we create the server/client
        # sockets in a specific order.
        self.server.listen()

        # Override the listener timeout if a shorter one was requested (e.g.
        # for assert_connection_rejected where we expect the accept to fail).
        if self.timeout is not None:
            listener = getattr(self.server, 'tls_listener', None) or getattr(self.server, 'listener', None)
            if listener is not None:
                listener.settimeout(self.timeout)

        # note: there might be a bug in the way we handle unix sockets. Ideally,
        # the check below should be the first thing we do in SocketPair().
        TcpClient(STATUS_PORT).connect(20)

        self.client.connect()
        self.server.accept()

    def validate_can_send_from_client(self, string, msg):
        encoded = bytes(string, 'utf-8')
        self.client.get_socket().send(encoded)
        data = self.server.get_socket().recv(len(encoded))
        if data != encoded:
            raise Exception("did not received expected string")
        print_ok(msg)

    def validate_can_send_from_server(self, string, msg):
        encoded = bytes(string, 'utf-8')
        self.server.get_socket().send(encoded)
        data = self.client.get_socket().recv(len(encoded))
        if data != encoded:
            raise Exception("did not received expected string")
        print_ok(msg)

    def validate_closing_client_closes_server(self, msg):
        print_ok(msg)
        self.client.get_socket().shutdown(socket.SHUT_RDWR)
        self.client.get_socket().close()
        # if the tunnel doesn't close the connection, recv(1) will raise a
        # Timeout
        self.server.get_socket().recv(1)

    def validate_half_closing_client_closes_server(self, msg):
        print_ok(msg)
        # call shutdown for write (sends FIN), but don't close connection
        self.client.get_socket().shutdown(socket.SHUT_WR)
        # server should still be able to send data back, within the timeout
        self.server.get_socket().send(b'A')
        self.client.get_socket().recv(1)
        # if the tunnel doesn't close the connection (forwarding the FIN packet),
        # then recv(1) will raise a Timeout
        self.server.get_socket().recv(1)
        # cleanup
        self.client.get_socket().close()

    def validate_closing_server_closes_client(self, msg):
        print_ok(msg)
        self.server.get_socket().shutdown(socket.SHUT_RDWR)
        self.server.get_socket().close()
        # if the tunnel doesn't close the connection, recv(1) will raise a
        # Timeout
        self.client.get_socket().recv(1)

    def validate_half_closing_server_closes_client(self, msg):
        print_ok(msg)
        # call shutdown for write (sends FIN), but don't close connection
        self.server.get_socket().shutdown(socket.SHUT_WR)
        # client should still be able to send data back, within the timeout
        self.client.get_socket().send(b'A')
        self.server.get_socket().recv(1)
        # if the tunnel doesn't close the connection (forwarding the FIN packet),
        # then recv(1) will raise a Timeout
        self.client.get_socket().recv(1)
        # cleanup
        self.server.get_socket().close()

    def validate_client_cert(self, ou, msg):
        for i in range(1, 20):
            try:
                self.server.validate_client_cert(ou)
                print_ok(msg)
                return
            except Exception as e:
                print(e)
            print("validate client cert failed, trying again...")
            _poll_sleep(i)
            self.cleanup()
            self.connect()
        raise Exception("did not connect to expected peer.")

    def validate_tunnel_ou(self, ou, msg):
        peercert = self.client.get_socket().getpeercert()
        actual = _get_ou(peercert)
        if actual != ou:
            raise Exception("did not connect to expected peer: got {}, wanted: {}".format(
                            actual, ou))
        print_ok(msg)
