Ghostunnel
==========

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/ghostunnel/master/LICENSE) [![release](https://img.shields.io/github/release/square/ghostunnel.svg?style=flat)](https://github.com/square/ghostunnel/releases) [![docker](https://img.shields.io/badge/docker-hub-blue.svg?style=flat)](https://hub.docker.com/r/squareup/ghostunnel) [![travis](https://img.shields.io/travis/square/ghostunnel/master.svg?maxAge=3600&logo=travis&label=travis)](https://travis-ci.org/square/ghostunnel) [![appveyor](https://img.shields.io/appveyor/ci/csstaub/ghostunnel-58e7k.svg?maxAge=3600&logo=appveyor&label=appveyor)](https://ci.appveyor.com/project/csstaub/ghostunnel-58e7k) [![coverage](https://coveralls.io/repos/github/square/ghostunnel/badge.svg?branch=master)](https://coveralls.io/r/square/ghostunnel) [![report](https://goreportcard.com/badge/github.com/square/ghostunnel)](https://goreportcard.com/report/github.com/square/ghostunnel)

👻

Ghostunnel is a simple TLS proxy with mutual authentication support for
securing non-TLS backend applications.

Ghostunnel supports two modes, client mode and server mode. Ghostunnel in
server mode runs in front of a backend server and accepts TLS-secured
connections, which are then proxied to the (insecure) backend. A backend can be
a TCP domain/port or a UNIX domain socket. Ghostunnel in client mode accepts
(insecure) connections through a TCP or UNIX domain socket and proxies them to
a TLS-secured service. In other words, ghostunnel is a replacement for stunnel.

**Supported platforms**: Ghostunnel is developed primarily for Linux on x86-64
platforms, although it should run on any UNIX system that exposes `SO_REUSEPORT`,
including Darwin (macOS), FreeBSD, OpenBSD and NetBSD. Ghostunnel also supports
running on Windows, though with a reduced feature set. We recommend running on
x86-64 to benefit from constant-time implementations of cryptographic algorithms
that are not available on other platforms.

See `ghostunnel --help`, `ghostunnel server --help` and `ghostunnel client --help`.

Features
========

**[Access control](#access-control-flags)**: Ghostunnel enforces mutual
authentication by requiring a valid client certificate for all connections. We
also support access control via checks on the subject (or subject alternative
names) of a client certificate. This is useful for restricting access to
services that don't have native access control.

**[Certificate hotswapping](#certificate-hotswapping)**: Ghostunnel can reload
certificates at runtime without dropping existing connections. Certificate
reloading can be triggered with a signal or on a regular time interval. This
allows short-lived certificates to be used with ghostunnel, new certificates
will get picked up transparently. And on platforms with `SO_REUSEPORT` support,
restarts can be done with minimal downtime.

**[Monitoring and metrics](#metrics--profiling)**: Ghostunnel has a built-in
status feature that can be used to collect metrics and monitor a running
instance. Metrics can be fed into Graphite (or other systems) to see number of
open connections, rate of new connections, connection lifetimes, timeouts, and
other info.

**Emphasis on security**: We have put some thought into making ghostunnel
secure by default and prevent accidental misconfiguration. For example,  we
always negotiate TLS v1.2 and only use safe cipher suites. Ghostunnel also
supports PKCS#11 which makes it possible to use Hardware Security Modules
(HSMs) to protect private keys, and we have a [BUG-BOUNTY](BUG-BOUNTY.md) that
pays rewards for security findings. 

Getting Started
===============

To get started and play around with the implementation, you will need to
generate some test certificates. If you want to bootstrap a full PKI, one
good way to get started is to use a package like
[square/certstrap](https://github.com/square/certstrap). If you only need
some test certificates for playing around with the tunnel, you can find
some pre-generated ones in the `test-keys` directory (alongside instructions
on how to generate new ones with OpenSSL).

### Install

Ghostunnel is available through [GitHub releases][rel] and through [Docker Hub][hub].

Binaries can be built from source as follows (cross-compile requires Docker and [xgo][xgo]):

    # Compile for local architecture
    make ghostunnel

    # Cross-compile release binaries
    make -f Makefile.dist dist

Note that ghostunnel requires Go 1.11 or later to build, and CGO is required for
PKCS#11 support.  See also [CROSS-COMPILE](docs/CROSS-COMPILE.md) for
instructions on how to cross-compile a custom build with CGO enabled.

[rel]: https://github.com/square/ghostunnel/releases
[hub]: https://hub.docker.com/r/squareup/ghostunnel
[xgo]: https://github.com/karalabe/xgo

### Develop

Ghostunnel has an extensive suite of integration tests. Our integration test
suite requires Python 3.5 (or later) and [gocovmerge][gcvm] to run. We use [Go
modules][gomod] for managing vendored dependencies. 

To run tests:

    # Option 1: run unit & integration tests locally
    make test

    # Option 2: run unit & integration tests in a Docker container
    GO_VERSION=1.11 make docker-test

    # Open coverage information in browser
    go tool cover -html coverage-merged.out

For more information on how to contribute, please see the [CONTRIBUTING](CONTRIBUTING.md) file.

[gcvm]: https://github.com/wadey/gocovmerge
[gomod]: https://github.com/golang/go/wiki/Modules

Usage
=====

By default, ghostunnel runs in the foreground and logs to stderr. You can set
`--syslog` to log to syslog instead of stderr. If you want to run ghostunnel
in the background, we recommend using a service manager such as [systemd][systemd] or
[runit][runit], or use a wrapper such as [daemonize][daemonize] or [dumb-init][dumb-init].

[runit]: http://smarden.org/runit
[systemd]: https://www.freedesktop.org/wiki/Software/systemd
[daemonize]: http://software.clapper.org/daemonize
[dumb-init]: https://github.com/Yelp/dumb-init

### Certificates

Ghostunnel accepts two formats of keystores, either a PKCS#12 keystore or a
combined PEM file that contains both the certificate chain and private key.
Both formats can be used with the `--keystore` flag, ghostunnel will
automatically detect the file format and handle it appropriately. If you are
using a PKCS#12 keystore protected by a password, you will also need to pass
the `--storepass` flag. If you want to use ghostunnel with a PKCS#11 module,
see the section on PKCS#11 below.

In the event your certificate and key are not bundled together (for example
created by cert-manager in Kubernetes), you can use `--keystore <cert>`
and `--keystoreKeyPath <key-file>`.


### Server mode 

This is an example for how to launch ghostunnel in server mode, listening for
incoming TLS connections on `localhost:8443` and forwarding them to
`localhost:8080`. 

To set allowed clients, you must specify at least one of `--allow-all`,
`--allow-cn`, `--allow-ou`, `--allow-dns` or `--allow-uri`. All checks are made
against the certificate of the client. Multiple flags are treated as a logical
disjunction (OR), meaning clients can connect as long as any of the flags
matches (see [ACCESS-FLAGS](docs/ACCESS-FLAGS.md) for more information). In
this example, we assume that the CN of the client cert we want to accept
connections from is `client`.

Start a backend server:

    nc -l localhost 8080

Start a ghostunnel in server mode to proxy connections:

    ghostunnel server \
        --listen localhost:8443 \
        --target localhost:8080 \
        --keystore test-keys/server-keystore.p12 \
        --cacert test-keys/cacert.pem \
        --allow-cn client

Verify that clients can connect with their client certificate:

    openssl s_client \
        -connect localhost:8443 \
        -cert test-keys/client-combined.pem \
        -key test-keys/client-combined.pem \
        -CAfile test-keys/cacert.pem

Now we have a TLS proxy running for our backend service. We terminate TLS in
ghostunnel and forward the connections to the insecure backend.

### Client mode

This is an example for how to launch ghostunnel in client mode, listening on
`localhost:8080` and proxying requests to a TLS server on `localhost:8443`. 

Start a backend TLS server:

    openssl s_server \
        -accept 8443 \
        -cert test-keys/server-combined.pem \
        -key test-keys/server-combined.pem \
        -CAfile test-keys/cacert.pem

Start a ghostunnel with a client certificate to forward connections:

    ghostunnel client \
        --listen localhost:8080 \
        --target localhost:8443 \
        --keystore test-keys/client-combined.pem \
        --cacert test-keys/cacert.pem

Verify that we can connect to `8080`:

    nc -v localhost 8080

Now we have a TLS proxy running for our client. We take the insecure local
connection, wrap them in TLS, and forward them to the secure backend.

### Full tunnel (client plus server)

We can combine the above two examples to get a full tunnel. Note that you can
start the ghostunnels in either order.

Start netcat on port `8001`:

    nc -l localhost 8001

Start the ghostunnel server:

    ghostunnel server \
        --listen localhost:8002 \
        --target localhost:8001 \
        --keystore test-keys/server-combined.pem \
        --cacert test-keys/cacert.pem \
        --allow-cn client

Start the ghostunnel client:

    ghostunnel client \
        --listen localhost:8003 \
        --target localhost:8002 \
        --keystore test-keys/client-keystore.p12 \
        --cacert test-keys/cacert.pem

Verify that we can connect to `8003`:

    nc -v localhost 8003

Now we have a full tunnel running. We take insecure client connections, 
forward them to the server side of the tunnel via TLS, and finally terminate
and proxy the connection to the insecure backend.

Advanced Features
=================

### Access Control Flags

Ghostunnel supports different types of access control flags in both client and
server modes.  All checks are made against the certificate of the client or
server. Multiple flags are treated as a logical disjunction (OR), meaning
clients can connect as long as any of the flags matches. Ghostunnel is
compatible with [SPIFFE][spiffe] [X.509 SVIDs][svid].

See [ACCESS-FLAGS](docs/ACCESS-FLAGS.md) for details.

[spiffe]: https://spiffe.io/
[svid]: https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md

### Certificate Hotswapping

To trigger a reload, simply send `SIGUSR1` to the process or set a time-based
reloading interval with the `--timed-reload` flag. This will cause ghostunnel
to reload the certificate and private key from the files on disk. Once
successful, the reloaded certificate will be used for new connections going
forward.

Additionally, ghostunnel uses `SO_REUSEPORT` to bind the listening socket on
platforms where it is supported (Linux, Apple macOS, FreeBSD, NetBSD, OpenBSD
and DragonflyBSD). This means a new ghostunnel can be started on the same
host/port before the old one is terminated, to minimize dropped connections (or
avoid them entirely depending on how the OS implements the `SO_REUSEPORT`
feature).

Note that if you are using an HSM/PKCS#11 module, only the certificate will
be reloaded. It is assumed that the private key in the HSM remains the same.
This means the updated/reissued certificate much match the private key that
was loaded from the HSM previously, everything else works the same.

### Metrics & Profiling

Ghostunnel has a notion of "status port", a TCP port (or UNIX socket) that can
be used to expose status and metrics information over HTTPS. The status port
feature can be controlled via the `--status` flag. Profiling endpoints on the
status port can be enabled with `--enable-pprof`.

See [METRICS](docs/METRICS.md) for details.

### HSM/PKCS#11 support

Ghostunnel has support for loading private keys from PKCS#11 modules, which
should work with any hardware security module that exposes a PKCS#11 interface.

See [HSM-PKCS11](docs/HSM-PKCS11.md) for details.

### macOS keychain support (experimental)

If ghostunnel has been compiled with build tag `certstore` (off by default,
requires macOS 10.12+) a new flag will be available that allows for loading
certificates from the macOS keychain. This is useful if you have identities
stored in your local keychain that you want to use with ghostunnel, e.g. if you
want your private key(s) to be backed by the SEP on newer Touch ID MacBooks.
Certificates from the keychain can be loaded by selecting them based on the
Common Name (CN) of the subject.

For example, if you have an identity with CN 'example' in your login keychain:

    ghostunnel client \
        --keychain-identity example \
        --listen localhost:8080 \
        --target example.com:443 \
        --cacert test-keys/cacert.pem

The command above launches a ghostunnel instance that uses the certificate and
private key with Common Name 'example' from your login keychain to proxy plaintext
connections from localhost:8080 to example.com:443.
