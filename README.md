Ghostunnel
==========

[![license](http://img.shields.io/badge/license-apache_2.0-red.svg?style=flat)](https://raw.githubusercontent.com/square/ghostunnel/master/LICENSE) [![build](https://img.shields.io/travis/square/ghostunnel/master.svg?style=flat)](https://travis-ci.org/square/ghostunnel)

👻

Ghostunnel is a simple SSL/TLS proxy with mutual authentication support for
securing non-TLS backend applications. Ghostunnel runs in front of a backend
service and accepts TLS-secured connections, which are then proxied to the
(insecure) backend. A backend can be a TCP domain/port or a UNIX socket path.
In other words, ghostunnel is a very limited replacement for stunnel in server
mode.

Features
========

***Authentication/access control***: Ghostunnel enforces mutual authentication
by always requiring a valid client certificate. We also support access control
via checks of the CN/OU fields on the subject of a client certificate. This is
useful for restricting access to services that don't have native access
control. 

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

Getting started
===============

To get started and play around with the implementation, you will need to 
generate some test certificates. If you want to bootstrap a full PKI, one
good way to get started is to use a package like
[square/certstrap](https://github.com/square/certstrap). If you only need
some test certificates for playing around with the tunnel, you can find
some pre-generated ones in the `test-keys` directory (alongside instructions
on how to generate new ones with OpenSSL).

### Build

To build ghostunnel and run tests:

    make build
    make test

To update vendored dependencies:

    make update-depends

### Launch

This is a short example for how to launch ghostunnel listening for incoming
connections on `localhost:8443` and forwarding them to `localhost:8080`. We
assume that `server.p12` is a PKCS12 keystore with the certificate and private
key for the server, and that `root.crt` contains your trusted root certificate(s).

To set allowed clients, you must specify at least one of `--allow-all`,
`--allow-cn` or `--allow-ou`.  It's possible to use both `--allow-cn` and
`--allow-ou` together or to specify them repeatedly to allow multiple CN/OU
values. In this example, we assume that the CN of the client cert we want to
accept connections from is `client`.

Start a ghostunnel with a server certificate:

    ghostunnel \
        --listen 127.0.0.1:8443 \
        --target 127.0.0.1:8080 \
        --keystore test-keys/server.p12 \
        --cacert test-keys/root.crt \
        --allow-cn client

Verify that the client(s) can connect with their client certificate:

    openssl s_client \
        -connect 127.0.0.1:8443 \
        -cert test-keys/client.crt \
        -key test-keys/client.key \
        -CAfile test-keys/root.crt

If `openssl s_client` can connect, then the tunnel should be working as
intended! Be sure to check the logs to see incoming connections and other
information. Note that by default ghostunnel logs to stderr and runs in the
foreground (set `--syslog` to log to syslog). For deamonization, we recommend
using a utility such as [daemonize](http://software.clapper.org/daemonize/).
For an example on how to use ghostunnel in a Docker container, see the `docker`
subdirectory.
