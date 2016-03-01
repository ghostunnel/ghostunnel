Ghostunnel
==========

[![license](http://img.shields.io/badge/license-apache_2.0-red.svg?style=flat)](https://raw.githubusercontent.com/square/ghostunnel/master/LICENSE)
[![build](https://img.shields.io/travis/square/ghostunnel/master.svg?style=flat)](https://travis-ci.org/square/ghostunnel)
[![report](https://goreportcard.com/badge/github.com/square/ghostunnel)](https://goreportcard.com/report/github.com/square/ghostunnel)

👻

Ghostunnel is a simple SSL/TLS proxy with mutual authentication support for
securing non-TLS backend applications.

* Ghostunnel in server mode runs in front of a backend service and accepts
  TLS-secured connections, which are then proxied to the (insecure) backend. A
  backend can be a TCP domain/port or a UNIX socket path.

* Ghostunnel in client mode accepts (insecure) TCP or UNIX domain socket
  connections and proxies them to a TLS-secured service.

In other words, ghostunnel is a replacement for stunnel.

See `ghostunnel --help`, `ghostunnel server --help` and `ghostunnel client --help`.

Features
========

***Authentication/access control***: Ghostunnel enforces mutual authentication
by always requiring a valid client certificate. We also support access control
via checks of the CN/OU fields on the subject of a client certificate. This is
useful for restricting access to services that don't have native access control.

***Certificate hotswapping***: Ghostunnel can reload certificates at runtime
without dropping existing connections. To trigger a reload, simply send
`SIGUSR1` to the process. This will cause ghostunnel to reload the keystore
files and open a new listening socket (via `SO_REUSEPORT`). Once successful,
the old listening socket will be closed.

***Automatic reloading***: Ghostunnel can be configured to automatically reload
certificates. You can specify an interval with the `--timed-reload` flag. If
the timed reload flag is enabled, ghostunnel will reload the files periodically
and check for changes. If a change is detected, it will attempt to reload the
listener with the new certificates/private key.

***Emphasis on security***: We have put some thought into making ghostunnel secure
by default. In server mode, the target connection must live on localhost or
a UNIX socket (unless --unsafe-target is specified). In a similar way, in client
mode the listening socket must live on localhost or a UNIX socket (unless --unsafe-listen
is specified). Ghostunnel negotiates TLSv1.2 (by default) and uses safe ciphers.


Getting started
===============

To get started and play around with the implementation, you will need to
generate some test certificates. If you want to bootstrap a full PKI, one
good way to get started is to use a package like
[square/certstrap](https://github.com/square/certstrap). If you only need
some test certificates for playing around with the tunnel, you can find
some pre-generated ones in the `test-keys` directory (alongside instructions
on how to generate new ones with OpenSSL).

Note that by default ghostunnel logs to stderr and runs in the foreground. You
can set set `--syslog` to log to syslog. For daemonization, we recommend using
a utility such as [daemonize](http://software.clapper.org/daemonize/). For an
example on how to use ghostunnel in a Docker container, see the `docker`
subdirectory.

### Build

We use [glide](https://github.com/Masterminds/glide) for vendoring.
Use `go get github.com/Masterminds/glide` or `brew install glide` to install it.

Then, build ghostunnel and run tests:

    make build
    make test

If you want to update vendored dependencies:

    make update-depends

Ghostunnel is tested with Go 1.6, and our integration test suite requires
Python 3.5 with pyOpenSSL installed.

### Server mode 

This is an example for how to launch ghostunnel in server mode, listening for
incoming TLS connections on `localhost:8443` and forwarding them to
`localhost:8080`. 

To set allowed clients, you must specify at least one of `--allow-all`,
`--allow-cn`, `--allow-ou`, `--allow-dns-san`, or `--allow-ip-san`. It's
possible to use these together or to specify them repeatedly to allow multiple
clients. In this example, we assume that the CN of the client cert we want to
accept connections from is `client`.

Start a backend server:

    nc -l localhost 8080

Start a ghostunnel in server mode to proxy connections:

    ghostunnel server \
        --listen localhost:8443 \
        --target localhost:8080 \
        --keystore test-keys/server.p12 \
        --cacert test-keys/root.crt \
        --allow-cn client

Verify that clients can connect with their client certificate:

    openssl s_client \
        -connect localhost:8443 \
        -cert test-keys/client.crt \
        -key test-keys/client.key \
        -CAfile test-keys/root.crt

Now we have a TLS proxy running for our backend service. We terminate TLS in
ghostunnel and forward the connections to the insecure backend.

### Client mode

This is an example for how to launch ghostunnel in client mode, listening on
`localhost:8080` and proxying requests to a TLS server on `localhost:8443`. 

Start a backend TLS server:

    openssl s_server \
        -accept 8443 \
        -cert test-keys/server.crt \
        -key test-keys/server.key \
        -CAfile test-keys/root.crt

Start a ghostunnel with a client certificate to forward connections:

    ghostunnel client \
        --listen localhost:8080 \
        --target localhost:8443 \
        --keystore test-keys/client.p12 \
        --cacert test-keys/root.crt

Verify that we can connect to `8080`:

    nc -v localhost 8080

Not we have a TLS proxy running for our client. We take the insecure local
connection, wrap them in TLS, and forward them to the secure backend.

### Full tunnel (client plus server)

We can combine the above two examples to get a full tunnel. Note that you can
start the ghostunnels in either order.

Start netcat on port 8001:

    nc -l localhost 8001

Start the ghostunnel server:

    ghostunnel server \
        --listen localhost:8002 \
        --target localhost:8001 \
        --keystore test-keys/server.p12 \
        --cacert test-keys/root.crt \
        --allow-cn client

Start the ghostunnel client:

    ghostunnel client \
        --listen localhost:8003 \
        --target localhost:8002 \
        --keystore test-keys/client.p12 \
        --cacert test-keys/root.crt

Verify that we can connect to `8003`:

    nc -v localhost 8003

Now we have a full tunnel running. We take insecure client connections, 
forward them to the server side of the tunnel via TLS, and finally terminate
and proxy the connection to the insecure backend.
