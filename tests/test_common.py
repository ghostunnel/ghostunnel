from subprocess import call
from tempfile import mkstemp, mkdtemp
import OpenSSL.crypto as crypto
import socketserver, threading, time, socket, ssl, os, base64, textwrap, urllib.request

FNULL = open(os.devnull, 'w')
LOCALHOST = '127.0.0.1'
STATUS_PORT = 13100
TIMEOUT = 5

# Helper class to create root + signed certs
class RootCert:
  def __init__(self, name):
    self.name = name
    self.leaf_certs = []
    print_ok("generating {0}.key, {0}.crt".format(name))
    call('openssl genrsa -out {0}.key 1024'.format(name), shell=True, stderr=FNULL)
    call('openssl req -x509 -new -key {0}.key -days 5 -out {0}_temp.crt -subj /C=US/ST=CA/O=ghostunnel/OU={0}'.format(name), shell=True)
    os.rename("{0}_temp.crt".format(name), "{0}.crt".format(name))
    call('chmod 600 {0}.key'.format(name), shell=True)

  def create_signed_cert(self, ou, san="IP:127.0.0.1,IP:::1,DNS:localhost"):
    print_ok("generating {0}.key, {0}.crt, {0}.p12".format(ou))
    fd, openssl_config = mkstemp(dir='.')
    os.write(fd, "extendedKeyUsage=clientAuth,serverAuth\n".encode('utf-8'))
    os.write(fd, "subjectAltName = {0}".format(san).encode('utf-8'))
    call("openssl genrsa -out {0}.key 1024".format(ou), shell=True, stderr=FNULL)
    call("openssl req -new -key {0}.key -out {0}.csr -subj /C=US/ST=CA/O=ghostunnel/OU={0}".format(ou), shell=True, stderr=FNULL)
    call("chmod 600 {0}.key".format(ou), shell=True)
    call("openssl x509 -req -in {0}.csr -CA {1}.crt -CAkey {1}.key -CAcreateserial -out {0}_temp.crt -days 5 -extfile {2}".format(ou, self.name, openssl_config), shell=True, stderr=FNULL)
    call("openssl pkcs12 -export -out {0}_temp.p12 -in {0}_temp.crt -inkey {0}.key -password pass:".format(ou), shell=True)
    os.rename("{0}_temp.crt".format(ou), "{0}.crt".format(ou))
    os.rename("{0}_temp.p12".format(ou), "{0}.p12".format(ou))
    os.close(fd)
    os.remove(openssl_config)
    self.leaf_certs.append(ou)

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

######################### Abstract #########################
class MySocket():
  def __init__(self):
    self.socket = None

  def get_socket(self):
    return self.socket

  def cleanup(self):
    self.socket = None # automatically calls close()

######################### TCP #########################

class TcpClient(MySocket):
  def __init__(self, port):
    super().__init__()
    self.port = port

  def connect(self, attempts=1, msg=''):
    for i in range(0, attempts):
      try:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(TIMEOUT)
        self.socket.connect((LOCALHOST, self.port))
        print_ok(msg)
        return
      except Exception as e:
        print(e)
      print("failed to connect to {0}. Trying again...".format(self.port))
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
#    self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
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
  def __init__(self, cert, ca, port):
    super().__init__()
    self.cert = cert
    self.ca = ca
    self.port = port
    self.tls_listener = None

  def connect(self, attempts=1, peer=None):
    for i in range(0, attempts):
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        if self.cert != None:
          self.socket = ssl.wrap_socket(sock,
            keyfile='{0}.key'.format(self.cert),
            certfile='{0}.crt'.format(self.cert),
            ca_certs='{0}.crt'.format(self.ca),
            cert_reqs=ssl.CERT_REQUIRED)
        else:
          self.socket = ssl.wrap_socket(sock,
            ca_certs='{0}.crt'.format(self.ca),
            cert_reqs=ssl.CERT_REQUIRED)
        self.socket.connect((LOCALHOST, self.port))

        if peer != None:
          if self.socket.getpeercert()['subject'][3][0][1] == peer:
            return self
          else:
            print("Did not connect to expected peer: {0}".format(self.socket.getpeercert()))
        else:
          return self
      except Exception as e:
        print(e)
        if attempts==1:
          raise e
      print("Trying to connect to {0}...".format(self.port))
      time.sleep(1)
    raise Exception("did not connect to peer")

class TlsServer(MySocket):
  def __init__(self, cert, ca, port, cert_reqs=ssl.CERT_REQUIRED):
    super().__init__()
    self.cert = cert
    self.ca = ca
    self.port = port
    self.cert_reqs = cert_reqs
    self.tls_listener = None

  def listen(self):
    super().listen()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(TIMEOUT)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    listener.bind((LOCALHOST, self.port))
    listener.listen(1)
    self.tls_listener = ssl.wrap_socket(listener,
      server_side=True,
      keyfile='{0}.key'.format(self.cert),
      certfile='{0}.crt'.format(self.cert),
      ca_certs='{0}.crt'.format(self.ca),
      cert_reqs=self.cert_reqs)

  def accept(self):
    self.socket, _ = self.tls_listener.accept()
    self.socket.settimeout(TIMEOUT)
    self.listener.close()

  def validate_client_cert(self, ou):
    if self.socket.getpeercert()['subject'][3][0][1] == ou:
      return
    raise Exception("did not connect to expected peer: ", self.server_sock.getpeercert())

  def cleanup(self):
    super().cleanup()
    self.tls_listener = None

######################### UNIX SOCKET #########################

class UnixClient(MySocket):
  def __init__(self, port):
    super().__init__()
    self.port = port

  def connect(self, attempts=1, msg=''):
    for i in range(0, attempts):
      try:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(TIMEOUT)
        self.socket.connect((LOCALHOST, self.port))
        print_ok(msg)
        return
      except Exception as e:
        print(e)
      print("failed to connect to {0}. Trying again...".format(self.port))
      time.sleep(1)

    raise Exception("Failed to connect to {0}".format(self.port))

class UnixServer(MySocket):
  def __init__(self):
    super().__init__()
    self.socket_path = os.path.join(mkdtemp(), 'ghostunnel-test-socket')
    self.listener = None

  def get_socket_path(self):
    return self.socket_path

  def listen(self):
    self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.listener.settimeout(TIMEOUT)
    self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.listener.bind(self.socket_path)
    self.listener.listen(1)

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
    self.client.get_socket().shutdown(socket.SHUT_RDWR)
    self.client.get_socket().close()
    # if the tunnel doesn't close the connection, recv(1) will raise a Timeout
    self.server.get_socket().recv(1)

  def validate_closing_server_closes_client(self, msg):
    self.server.get_socket().shutdown(socket.SHUT_RDWR)
    self.server.get_socket().close()
    # if the tunnel doesn't close the connection, recv(1) will raise a Timeout
    self.client.get_socket().recv(1)

  def validate_client_cert(self, ou, msg):
    for i in range(1, 20):
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
    if peercert['subject'][3][0][1] != ou:
      raise Exception("did not connect to expected peer: ", peercert)
    print_ok(msg)
