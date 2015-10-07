Ghostunnel
==========

Ghostunnel is a simple SSL/TLS proxy with support mutual authentication for
securing non-TLS services such as Redis. Ghostunnel runs in front of a backend
service and accepts TLS-secured connections, which are then forwarded to the
backend.

Ghostunnel supports transparent restarts via `SO_REUSEPORT`. To reload the
process, simply send the `SIGUSR1` signal. This spawns a child process which
reloads the certificate and private key. The child will start up, attempt to
open the socket with `SO_REUSEPORT`, and start listening for new connections.
Once the listening socket is open, the child will send `SIGTERM` to the parent
to indicate successful startup. The parent will catch the `SIGTERM` and
gracefully shut down. This allows for hotswapping certificates without
dropping existing connections.

Usage
=====

    ghostunnel --listen=LISTEN --target=TARGET --client=CLIENT --key=KEY --cert=CERT --cacert=CACERT [<flags>]
    
    Flags:
      --help           Show help (also see --help-long and --help-man).
      --listen=LISTEN  Address and port to listen on
      --target=TARGET  Address to foward connections to
      --client=CLIENT  Expected client organizational unit name (can be repeated)
      --key=KEY        Path to private key file (PEM/PKCS1)
      --cert=CERT      Path to certificate chain file (PEM/X509)
      --cacert=CACERT  Path to certificate authority bundle file (PEM/X509)
      --syslog         Send logs to syslog instead of stderr
      --graceful       Send SIGTERM to parent after startup (internal)

