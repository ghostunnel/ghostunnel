# NAME

ghostunnel

# SYNOPSIS

**ghostunnel \[\<flags\>\] \<command\> \[\<args\> \...\]**

:   # DESCRIPTION

A simple SSL/TLS proxy with mutual authentication for securing non-TLS
services.

# OPTIONS

**\--help**

:   Show context-sensitive help (also try \--help-long and \--help-man).

**\--keystore=PATH**

:   Path to keystore (combined PEM with cert/key, or PKCS12 keystore).

**\--cert=PATH**

:   Path to certificate (PEM with certificate chain).

**\--key=PATH**

:   Path to certificate private key (PEM with private key).

**\--storepass=PASS**

:   Password for keystore (if using PKCS keystore, optional).

**\--cacert=CACERT**

:   Path to CA bundle file (PEM/X509). Uses system trust store by
    default.

**\--use-workload-api**

:   If true, certificate and root CAs are retrieved via the SPIFFE
    Workload API

**\--use-workload-api-addr=ADDR**

:   If set, certificates and root CAs are retrieved via the SPIFFE
    Workload API at the specified address (implies \--use-workload-api)

**\--timed-reload=DURATION**

:   Reload keystores every given interval (e.g. 300s), refresh
    listener/client on changes.

**\--shutdown-timeout=5m**

:   Process shutdown timeout. Terminates after timeout even if
    connections still open.

**\--connect-timeout=10s**

:   Timeout for establishing connections, handshakes.

**\--close-timeout=10s**

:   Timeout for closing connections when one side terminates.

**\--max-conn-lifetime=0s**

:   Maximum lifetime for connections post handshake, no matter what.
    Zero means infinite.

**\--max-concurrent-conns=0**

:   Maximum number of concurrent connections to handle in the proxy.
    Zero means infinite.

**\--metrics-graphite=ADDR**

:   Collect metrics and report them to the given graphite instance (raw
    TCP).

**\--metrics-url=URL**

:   Collect metrics and POST them periodically to the given URL (via
    HTTP/JSON).

**\--metrics-prefix=PREFIX**

:   Set prefix string for all reported metrics (default: ghostunnel).

**\--metrics-interval=30s**

:   Collect (and post/send) metrics every specified interval.

**\--status=ADDR**

:   Enable serving /\_status and /\_metrics on given HOST:PORT (or
    unix:SOCKET).

**\--enable-pprof**

:   Enable serving /debug/pprof endpoints alongside /\_status (for
    profiling).

**\--enable-shutdown**

:   Enable serving a /\_shutdown endpoint alongside /\_status to allow
    terminating via HTTP.

**\--quiet=**

:   Silence log messages (can be all, conns, conn-errs, handshake-errs;
    repeat flag for more than one)

**\--syslog**

:   Send logs to syslog instead of stderr.

**\--keychain-identity=CN**

:   Use local keychain identity with given serial/common name (instead
    of keystore file).

**\--keychain-issuer=CN**

:   Use local keychain identity with given issuer name (instead of
    keystore file).

**\--keychain-require-token**

:   Require keychain identity to be from a physical token (sets \'access
    group\' to \'token\').

**\--pkcs11-module=PATH**

:   Path to PKCS11 module (SO) file (optional).

**\--pkcs11-token-label=LABEL**

:   Token label for slot/key in PKCS11 module (optional).

**\--pkcs11-pin=PIN**

:   PIN code for slot/key in PKCS11 module (optional).

**\--version**

:   Show application version.

# COMMANDS

## **help \[\<command\>\...\]**

Show help.

## **server \--listen=ADDR \--target=ADDR \[\<flags\>\]**

Server mode (TLS listener -\> plain TCP/UNIX target).

**\--listen=ADDR**

:   Address and port to listen on (can be HOST:PORT, unix:PATH,
    systemd:NAME or launchd:NAME).

**\--target=ADDR**

:   Address to forward connections to (can be HOST:PORT or unix:PATH).

**\--target-status=\"\"**

:   Address to target for status checking downstream healthchecks.
    Defaults to a TCP healthcheck if this flag is not passed.

**\--proxy-protocol**

:   Enable PROXY protocol v2 to signal connection info to backend

**\--unsafe-target**

:   If set, does not limit target to localhost, 127.0.0.1, \[::1\], or
    UNIX sockets.

**\--allow-all**

:   Allow all clients, do not check client cert subject.

**\--allow-cn=CN**

:   Allow clients with given common name (can be repeated).

**\--allow-ou=OU**

:   Allow clients with given organizational unit name (can be repeated).

**\--allow-dns=DNS**

:   Allow clients with given DNS subject alternative name (can be
    repeated).

**\--allow-uri=URI**

:   Allow clients with given URI subject alternative name (can be
    repeated).

**\--allow-policy=BUNDLE**

:   Allow passing the location of an OPA bundle.

**\--allow-query=QUERY**

:   Allow defining a query to validate against the client certificate
    and the rego policy.

**\--disable-authentication**

:   Disable client authentication, no client certificate will be
    required.

**\--auto-acme-cert=FQDN**

:   Automatically obtain a certificate via ACME for the specified FQDN

**\--auto-acme-email=EMAIL**

:   Email address associated with all ACME requests

**\--auto-acme-agree-to-tos**

:   Agree to the Terms of Service of the ACME CA

**\--auto-acme-ca=https://some-acme-ca.example.com/**

:   Specify the URL to the ACME CA. Defaults to Let\'s Encrypt if not
    specified.

**\--auto-acme-testca=https://testing.some-acme-ca.example.com/**

:   Specify the URL to the ACME CA\'s Test/Staging environment. If set,
    all requests will go to this CA and \--auto-acme-ca will be ignored.

## **client \--listen=ADDR \--target=ADDR \[\<flags\>\]**

Client mode (plain TCP/UNIX listener -\> TLS target).

**\--listen=ADDR**

:   Address and port to listen on (can be HOST:PORT, unix:PATH,
    systemd:NAME or launchd:NAME).

**\--target=ADDR**

:   Address to forward connections to (must be HOST:PORT).

**\--unsafe-listen**

:   If set, does not limit listen to localhost, 127.0.0.1, \[::1\], or
    UNIX sockets.

**\--override-server-name=NAME**

:   If set, overrides the server name used for hostname verification.

**\--proxy=URL**

:   If set, connect to target over given proxy (HTTP CONNECT or SOCKS5).
    Must be a proxy URL.

**\--verify-cn=CN**

:   Allow servers with given common name (can be repeated).

**\--verify-ou=OU**

:   Allow servers with given organizational unit name (can be repeated).

**\--verify-dns=DNS**

:   Allow servers with given DNS subject alternative name (can be
    repeated).

**\--verify-uri=URI**

:   Allow servers with given URI subject alternative name (can be
    repeated).

**\--verify-policy=BUNDLE**

:   Allow passing the location of an OPA bundle.

**\--verify-query=QUERY**

:   Allow defining a query to validate against the client certificate
    and the rego policy.

**\--disable-authentication**

:   Disable client authentication, no certificate will be provided to
    the server.
