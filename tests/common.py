from subprocess import call, Popen
from tempfile import mkstemp, mkdtemp
import json
import platform
import sys
import time
import socket
import ssl
import os
import urllib.request

FNULL = open(os.devnull, 'w')
LOCALHOST = '127.0.0.1'
STATUS_PORT = 13100
TIMEOUT = 5

def run_ghostunnel(args, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, prefix=None):
    """Helper to run ghostunnel in integration test mode"""

    # Set lower than default timeouts to speed up tests 
    if not any('shutdown-timeout' in f for f in args):
        args.append('--shutdown-timeout=0.1s')
    if not any('close-timeout' in f for f in args):
        args.append('--close-timeout=1s')

    # Enable landlock in integration tests, unless we're using PKCS11 modules.
    # Because PKCS11 modules are arbitrary SO files they can do anything at
    # runtime, and we can't guarantee that our landlock rules will work for
    # them.
    if not any('pkcs11-module' in f for f in args) and platform.system() == "Linux":
        args.append('--use-landlock')

    # Pass args through env var into integration test hook
    env = os.environ.copy()
    env["SYSTEMD_LOG_TARGET"] = "console"
    env["SYSTEMD_LOG_LEVEL"] = "debug"
    env["GHOSTUNNEL_INTEGRATION_TEST"] = "true"
    env["GHOSTUNNEL_INTEGRATION_ARGS"] = json.dumps(args)

    # Run it, hook up stdout/stderr if desired
    test = os.path.basename(sys.argv[0]).replace('.py', '.profile')
    cmd = [
        '../ghostunnel.test',
        '-test.run=TestIntegrationMain',
        '-test.coverprofile=../coverage/{0}'.format(test)
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
    else:
        print_ok("OK (terminated)")

def terminate(ghostunnel):
    """Gracefully terminate ghostunnel (with timeout)"""
    print_ok("terminating ghostunnel instance")
    try:
        if ghostunnel:
            ghostunnel.terminate()
            for _ in range(0, 10):
                try:
                    ghostunnel.wait(timeout=1)
                except BaseException:
                    pass
                if ghostunnel.returncode is not None:
                    print_ok("ghostunnel stopped with exit code {0}".format(
                        ghostunnel.returncode))
                    return
                time.sleep(1)
            print_ok("timeout, killing ghostunnel")
            ghostunnel.kill()
    except BaseException:
        pass

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
    def __init__(self, name):
        self.name = name
        self.leaf_certs = []
        print_ok("generating {0}.key, {0}.crt".format(name))
        call(
            'openssl genrsa -out {0}.key 2048'.format(name),
            shell=True,
            stderr=FNULL)
        call(
            'openssl req -x509 -new -key {0}.key -days 5 -out {0}_temp.crt -addext "keyUsage = digitalSignature, cRLSign, keyCertSign" -subj /C=US/ST=CA/O=ghostunnel/OU={0}'.format(name),
            shell=True)
        os.rename("{0}_temp.crt".format(name), "{0}.crt".format(name))
        call('chmod 600 {0}.key'.format(name), shell=True)

    def create_signed_cert(self, cn_and_ou, san="IP:127.0.0.1,IP:::1,DNS:localhost"):
        print_ok("generating {0}.key, {0}.crt, {0}.p12".format(cn_and_ou))
        fd, openssl_config = mkstemp(dir='.')
        os.write(fd, "extendedKeyUsage=clientAuth,serverAuth\n".encode('utf-8'))
        os.write(fd, "subjectAltName = {0},DNS:{1}".format(san, cn_and_ou).encode('utf-8'))
        call("openssl genrsa -out {0}.key 2048".format(cn_and_ou),
             shell=True, stderr=FNULL)
        call(
            "openssl req -new -key {0}.key -out {0}.csr -subj /CN={0}/C=US/ST=CA/O=ghostunnel/OU={0}".format(cn_and_ou),
            shell=True,
            stderr=FNULL)
        call("chmod 600 {0}.key".format(cn_and_ou), shell=True)
        call(
            "openssl x509 -req -in {0}.csr -CA {1}.crt -CAkey {1}.key -CAcreateserial -out {0}_temp.crt -days 5 -extfile {2}".format(
                cn_and_ou,
                self.name,
                openssl_config),
            shell=True,
            stderr=FNULL)
        call(
            "openssl pkcs12 -export -out {0}_temp.p12 -in {0}_temp.crt -inkey {0}.key -password pass:".format(cn_and_ou),
            shell=True)
        os.rename("{0}_temp.crt".format(cn_and_ou), "{0}.crt".format(cn_and_ou))
        os.rename("{0}_temp.p12".format(cn_and_ou), "{0}.p12".format(cn_and_ou))
        os.close(fd)
        os.remove(openssl_config)
        self.leaf_certs.append(cn_and_ou)

    def __del__(self):
        RootCert.cleanup_certs([self.name])
        RootCert.cleanup_certs(self.leaf_certs)

    @staticmethod
    def cleanup_certs(names):
        for name in names:
            for ext in ["crt", "key", "csr", "srl", "p12"]:
                try:
                    os.remove('{0}.{1}'.format(name, ext))
                except OSError:
                    pass

def print_ok(msg):
    print(("\033[92m{0}\033[0m".format(msg)))

def wrap_socket(socket, keyfile=None, certfile=None, ca_certs=None, cert_reqs=ssl.CERT_REQUIRED, server_side=False):
    ctx = ssl.SSLContext();
    if certfile is not None and keyfile is not None:
        ctx.load_cert_chain(certfile, keyfile)
    if ca_certs is not None:
        ctx.load_verify_locations(cafile=ca_certs)
    ctx.verify_mode = cert_reqs;
    return ctx.wrap_socket(socket, server_side=server_side);

def urlopen(path):
    context = ssl.create_default_context(cafile='root.crt')
    return urllib.request.urlopen(path, context=context)


######################### Abstract #########################


class MySocket():
    def __init__(self):
        self.socket = None

    def get_socket(self):
        return self.socket

    def cleanup(self):
        self.socket = None  # automatically calls close()

######################### TCP #########################


class TcpClient(MySocket):
    def __init__(self, port):
        super().__init__()
        self.port = port

    def connect(self, attempts=1, msg=''):
        for _ in range(0, attempts):
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
            time.sleep(1)

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
        self.listener.bind((LOCALHOST, self.port))
        self.listener.listen(1)

    def accept(self):
        self.socket, _ = self.listener.accept()
        self.socket.settimeout(TIMEOUT)
        self.listener.close()

    def cleanup(self):
        super().cleanup()
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
        for _ in range(0, attempts):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.verify_mode = ssl.CERT_REQUIRED
                if self.ca:
                    ctx.load_verify_locations(cafile=self.ca + '.crt')
                if self.cert:
                    ctx.load_cert_chain(self.cert + '.crt', self.cert + '.key')
                if self.min_version is not None:
                    ctx.minimum_version = self.min_version
                if self.max_version is not None:
                    ctx.maximum_version = self.max_version

                # First create TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                self.socket = ctx.wrap_socket(sock, server_hostname=peer if peer else LOCALHOST)
                self.socket.connect((LOCALHOST, self.port))
                return
            except Exception as e:
                print('connection attempt {0} failed, error: {1}'.format(_, e))
                time.sleep(1)

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

    def validate_client_cert(self, ou):
        if self.socket.getpeercert()['subject'][0][0][1] == ou:
            return
        raise Exception("did not connect to expected peer: got ",
                        self.socket.getpeercert()[0][0][1],
                        ", wanted: ", ou)

    def cleanup(self):
        super().cleanup()
        self.tls_listener = None

######################### UNIX SOCKET #########################


class UnixClient(MySocket):
    def __init__(self):
        super().__init__()
        self.socket_path = os.path.join(mkdtemp(), 'ghostunnel-test-socket')

    def get_socket_path(self):
        return self.socket_path

    def connect(self, attempts=1, msg=''):
        for _ in range(0, attempts):
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
            time.sleep(1)

        raise Exception("Failed to connect to {0}".format(self.socket_path))

    def cleanup(self):
        super().cleanup()
        self.socket = None
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
        if self.listening: return
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
        self.listener = None
        os.remove(self.socket_path)

######################### SocketPair #########################

# This is whacky but works. This class represents a pair of sockets which
# correspond to each end of the tunnel. The class lets you verify that sending
# data in one socket shows up on the other. It also allows testing that closing
# one socket closes the other.


class SocketPair():
    def __init__(self, client, server):
        self.client = client
        self.server = server
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
        self.server.get_socket().send('A'.encode('utf-8'))
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
        self.client.get_socket().send('A'.encode('utf-8'))
        self.server.get_socket().recv(1)
        # if the tunnel doesn't close the connection (forwarding the FIN packet), 
        # then recv(1) will raise a Timeout
        self.client.get_socket().recv(1)
        # cleanup
        self.server.get_socket().close()

    def validate_client_cert(self, ou, msg):
        for _ in range(1, 20):
            try:
                self.server.validate_client_cert(ou)
                print_ok(msg)
                return
            except Exception as e:
                print(e)
            print("validate client cert failed, trying again...")
            time.sleep(1)
            self.cleanup()
            self.connect()
        raise Exception("did not connect to expected peer.")

    def validate_tunnel_ou(self, ou, msg):
        peercert = self.client.get_socket().getpeercert()
        if peercert['subject'][0][0][1] != ou:
            raise Exception("did not connect to expected peer: got ",
                            peercert['subject'][0][0][1],
                            ", wanted: ", ou)
        print_ok(msg)
