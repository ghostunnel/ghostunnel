Ghostunnel
==========

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/ghostunnel/ghostunnel/master/LICENSE) [![release](https://img.shields.io/github/release/ghostunnel/ghostunnel.svg?style=flat)](https://github.com/ghostunnel/ghostunnel/releases) [![docker](https://img.shields.io/badge/docker-hub-blue.svg?style=flat)](https://hub.docker.com/r/ghostunnel/ghostunnel) [![test](https://img.shields.io/github/checks-status/ghostunnel/ghostunnel/master)](https://github.com/ghostunnel/ghostunnel/actions) [![coverage](https://img.shields.io/codecov/c/github/ghostunnel/ghostunnel/master)](https://app.codecov.io/gh/ghostunnel/ghostunnel/) [![report](https://goreportcard.com/badge/github.com/ghostunnel/ghostunnel)](https://goreportcard.com/report/github.com/ghostunnel/ghostunnel)

👻

Ghostunnel is a simple TLS proxy with mutual authentication support for
securing non-TLS backend applications.

Ghostunnel supports two modes, client mode and server mode. Ghostunnel in
server mode runs in front of a backend server and accepts TLS-secured
connections, which are then proxied to the (insecure) backend. A backend can be
a TCP domain/port or a UNIX domain socket. Ghostunnel in client mode accepts
(insecure) connections through a TCP or UNIX domain socket and proxies them to
a TLS-secured service. In other words, ghostunnel is a replacement for stunnel.

**Supported platforms**: Ghostunnel is developed primarily for Linux and Darwin
(macOS), although it should run on any UNIX system that exposes `SO_REUSEPORT`,
including FreeBSD, OpenBSD and NetBSD. Ghostunnel also supports running on
Windows, though with a reduced feature set. 

Features
========

**[Access control](#access-control-flags)**: Ghostunnel enforces mutual
authentication by requiring a valid client certificate for all connections.
Policies can enforce checks on the peer certificate in a connection, either
via simple flags or declarative policies using [Open 
Policy Agent](https://www.openpolicyagent.org). This is useful 
for restricting access to services that don't have native access control.

**[Certificate hotswapping](#certificate-hotswapping)**: Ghostunnel can reload
certificates at runtime without dropping existing connections. Certificates can
be loaded from disk, the [SPIFFE Workload API](https://spiffe.io), or a PKCS#11 module.
This allows short-lived certificates to be used with Ghostunnel as you can pick
up new certificates transparently.

**[ACME Support](#acme-support)**: In server mode, Ghostunnel can optionally
obtain and automatically renew a public TLS certificate via the ACME protocol,
such as through Let's Encrypt. Note that this requires a valid FQDN accessible
on the public internet for verification.

**[Monitoring and metrics](#metrics--profiling)**: Ghostunnel has a built-in
status feature that can be used to collect metrics and monitor a running
instance. Metrics can be fed into Graphite or Prometheus to see number of
open connections, rate of new connections, connection lifetimes, timeouts, and
other info.

**[Emphasis on security](BUG-BOUNTY.md)**: We have put some thought into making
Ghostunnel secure by default and prevent accidental misconfiguration. For example, 
we always negotiate TLS v1.2 (or greater) and only use safe cipher suites. Ghostunnel
also supports PKCS#11 which makes it possible to use Hardware Security Modules (HSMs)
to protect private keys. 

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

Please note that the official release binaries are best effort, and are usually
built directly via Github Actions on the latest available images. If you need
compatibility for specific OS versions, we recommend building yourself.

To build Ghostunnel, simply run:

    # Compile binary
    make ghostunnel

    # Generate man page
    make ghostunnel.man

Note that ghostunnel requires Go 1.22 or later to build, and CGO is required.

[rel]: https://github.com/ghostunnel/ghostunnel/releases
[hub]: https://hub.docker.com/r/ghostunnel/ghostunnel

### Develop

Ghostunnel has an extensive suite of integration tests. Our integration test
suite requires Python 3.5 (or later) and [gocovmerge][gcvm] to run. We use [Go
modules][gomod] for managing vendored dependencies. 

To run tests:

    # Option 1: run unit & integration tests locally
    make test

    # Option 2: run unit & integration tests in a Docker container
    # This also runs PKCS#11 integration tests using SoftHSM in the container
    GO_VERSION=1.23 make docker-test

    # Open coverage information in browser
    go tool cover -html coverage/all.profile

For more information on how to contribute, please see the [CONTRIBUTING](CONTRIBUTING.md) file.

[gcvm]: https://github.com/wadey/gocovmerge
[gomod]: https://github.com/golang/go/wiki/Modules

Usage
=====

To see available commands and flags, run `ghostunnel --help`. You can get more
information about a command by adding `--help` to the command, like `ghostunnel
server --help` or `ghostunnel client --help`.

By default, ghostunnel runs in the foreground and logs to stdout. You can set
`--syslog` to log to syslog instead of stdout. If you want to run ghostunnel
in the background, we recommend using a service manager such as [systemd][systemd] or
[runit][runit], or use a wrapper such as [daemonize][daemonize] or [dumb-init][dumb-init].

[runit]: http://smarden.org/runit
[systemd]: https://www.freedesktop.org/wiki/Software/systemd
[daemonize]: http://software.clapper.org/daemonize
[dumb-init]: https://github.com/Yelp/dumb-init

### Certificates

Ghostunnel accepts certificates in multiple different file formats.

The `--keystore` flag can take a PKCS#12 keystore or a combined PEM file with the
certificate chain and private key as input (format is auto-detected). The `--cert` /
`--key` flags can be used to load a certificate chain and key from separate PEM files
(instead of a combined one).

Ghostunnel also supports loading identities from the macOS keychain or the
SPIFFE Workload API and having private keys backed by PKCS#11 modules, see the
"Advanced Features" section below for more information.

### Server mode 

This is an example for how to launch ghostunnel in server mode, listening for
incoming TLS connections on `localhost:8443` and forwarding them to
`localhost:8080`. Note that while we use TCP sockets on `localhost` in this
example, both the listen and target flags can also accept paths to UNIX domain
sockets as their argument.

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

Ghostunnel also has experimental support for [Open Policy
Agent](https://www.openpolicyagent.org/) (OPA) policies. Policies can be
reloaded at runtime much like certificates.

See [ACCESS-FLAGS](docs/ACCESS-FLAGS.md) for details.

[spiffe]: https://spiffe.io/
[svid]: https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md

### Logging Options

You can silence specific types of log messages using the `--quiet=...` flag,
such as `--quiet=conns` or `--quiet=handshake-errs`. You can pass this flag
repeatedly if you want to silence multiple different kinds of log messages.

Supported values are:
* `all`: silences **all** log messages
* `conns`: silences log messages about new and closed connections. 
* `conn-errs`: silences log messages about connection errors encountered (post handshake). 
* `handshake-errs`: silences log messages about failed handshakes. 

In particular we recommend setting `--quiet=handshake-errs` if you are
running TCP health checks in Kubernetes on the listening port, and you
want to avoid seeing error messages from aborted connections on each health
check.

### Certificate Hotswapping

To trigger a reload, simply send `SIGHUP` to the process or set a time-based
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

### ACME Support

To have Ghostunnel automatically obtain and renew a public TLS certificate via ACME,
use the `--auto-acme-cert=` flag (e.g. - `--auto-acme-cert=myservice.example.com`).
You must also specify an email address so you will get notices from the CA about
potentially important certificate lifecycle events. Specify the email address with
the `--auto-acme-email=` flag. To use this feature, you must also specify the
`--auto-acme-agree-to-tos` flag to indicate your explicit agreement with the CA's
Terms of Service.

Ghostunnel defaults to using Let's Encrypt, but you can specify a different ACME
CA URL using the `--auto-acme-ca=` flag. If you wish to test Ghostunnel's ACME
features against a non-production ACME CA, use the `--auto-acme-testca=` flag.
If `--auto-acme-testca` is specified, all ACME interaction will be with the
specified test CA URL and the `--auto-acme-ca=` flag will be ignored.

ACME is only supported in server mode. Additionally, Ghostunnel must either be
listening to a public interface on tcp/443, or somehow have a public tcp/443
listening interface forwarded to it (e.g. - systemd socket, iptables, etc.). Public
DNS records must exist for a valid public DNS FQDN that resolves to the public
listening interface IP.
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

### SPIFFE Workload API

Ghostunnel has support for maintaining up-to-date, frequently rotated
identities and trusted CA certificates from the SPIFFE Workload API.

See [SPIFFE-WORKLOAD-API](docs/SPIFFE-WORKLOAD-API.md) for details.

### Socket Activation (experimental)

Ghostunnel supports socket activation via both systemd (on Linux) and launchd
(on macOS). Socket activation is support for the `--listen` and `--status`
flags, and can be used by passing an address of the form `systemd:<name>` or
`launchd:<name>`, where `<name>` should be the name of the socket as defined in
your systemd/launchd configuration.

See [SOCKET-ACTIVATION](docs/SOCKET-ACTIVATION.md) for examples.

### PROXY Protocol (experimental)

Ghostunnel in server mode supports signalling of transport connection information
to the backend using the [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
(v2), just pass the `--proxy-protocol` flag on startup. Note that the backend must
also support the PROXY protocol and must be configured to use it when setting
this option.

### MacOS Keychain Support (experimental)

Ghostunnel supports loading certificates from the macOS keychain. This is useful
if you have identities stored in your local keychain that you want to use with
ghostunnel, e.g. if you want your private key(s) to be backed by the SEP on newer
Touch ID MacBooks. Certificates from the keychain can be loaded by selecting them
based on the serial number, Common Name (CN) of the subject, or Common Name (CN)
of the issuer.

For example, to load an identity based on subject name login keychain:

    ghostunnel client \
        --keychain-identity <common-name-or-serial> \
        --listen unix:/path/to/unix/socket \
        --target example.com:443 \
        --cacert test-keys/cacert.pem

Or, if you'd like to load an identity by filtering on issuer name:

    ghostunnel client \
        --keychain-issuer <issuer-common-name> \
        --listen unix:/path/to/unix/socket \
        --target example.com:443 \
        --cacert test-keys/cacert.pem

Both commands above launch a ghostunnel instance that uses the certificate and
private key for the selected keychain identity to proxy plaintext connections from
a given UNIX socket to example.com:443. Note that combining both the identity and
issuer flags in one command will cause ghostunnel to select certificates where both
attributes match (matching with AND on both subject name/issuer).
