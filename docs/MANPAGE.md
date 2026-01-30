# NAME

ghostunnel

# SYNOPSIS

**ghostunnel \[\<flags\>\] \<command\> \[\<args\> \...\]**

# DESCRIPTION

A simple SSL/TLS proxy with mutual authentication for securing non-TLS services.

Ghostunnel supports two modes, client mode and server mode. Ghostunnel in server mode runs in front of a backend server and accepts TLS-secured connections, which are then proxied to the (insecure) backend. A backend can be a TCP domain/port or a UNIX domain socket. Ghostunnel in client mode accepts (insecure) connections through a TCP or UNIX domain socket and proxies them to a TLS-secured service.

For a more in-depth explanation, please see the README.md file (and docs folder) that shipped with Ghostunnel or view the latest docs on github.com/ghostunnel/ghostunnel.

# CERTIFICATES & PRIVATE KEYS

Ghostunnel supports multiple methods for loading certificates and private keys.

File-based formats:

> The **\--keystore** flag can take a PKCS#12 keystore or a combined PEM file with the certificate chain and private key as input (format is auto-detected). The **\--cert** and **\--key** flags can be used to load a certificate chain and key from separate PEM files (instead of a combined one).

SPIFFE Workload API:

> Ghostunnel can retrieve certificates and root CAs from the SPIFFE Workload API using the **\--use-workload-api** flag. This enables automatic certificate rotation and is useful in service mesh deployments. The Workload API socket location can be specified via the **SPIFFE_ENDPOINT_SOCKET** environment variable or the **\--use-workload-api-addr** flag.

ACME (Automatic Certificate Management):

> In server mode, Ghostunnel can automatically obtain and renew public TLS certificates using the ACME protocol (e.g., Let\'s Encrypt). Use **\--auto-acme-cert** with **\--auto-acme-email** and **\--auto-acme-agree-to-tos**. This requires Ghostunnel to be accessible on a public interface (tcp/443) with valid DNS records. The ACME CA URL can be specified with **\--auto-acme-ca** (defaults to Let\'s Encrypt).

PKCS#11 (Hardware Security Modules):

> Private keys can be stored in PKCS#11-compatible hardware security modules (HSMs). Use **\--cert** to specify the certificate chain file, and **\--pkcs11-module**, **\--pkcs11-token-label**, and **\--pkcs11-pin** to configure the HSM. PKCS#11 options can also be set via environment variables (**PKCS11_MODULE**, **PKCS11_TOKEN_LABEL**, **PKCS11_PIN**).

Keychain (macOS/Windows):

> On macOS and Windows, Ghostunnel can load certificates from the system keychain using **\--keychain-identity** (by subject CN/serial) or **\--keychain-issuer** (by issuer CN). On macOS, **\--keychain-require-token** can be used to require certificates from physical tokens (e.g., Touch ID MacBooks).

# EXAMPLE: SERVER MODE

Start a ghostunnel in server mode to proxy connections from localhost:8443 to localhost:8080, while only allowing connections from client certificates with CN=client:

        ghostunnel server \
            --listen localhost:8443 \
            --target localhost:8080 \
            --keystore server-keystore.p12 \
            --cacert cacert.pem \
            --allow-cn client

To set allowed clients, you must specify at least one of **\--allow-all**, **\--allow-cn**, **\--allow-ou**, **\--allow-dns**, **\--allow-uri**, or **\--allow-policy**. All checks are made against the certificate of the client. Multiple flags are treated as a logical disjunction (OR), meaning clients can connect as long as any of the flags match. To disable requiring client certificates, use **\--disable-authentication**.

# EXAMPLE: CLIENT MODE

Start a ghostunnel in client mode to proxy connections from localhost:8080 to localhost:8443, doing only hostname verification to validate the server certificate:

        ghostunnel client \
            --listen localhost:8080 \
            --target localhost:8443 \
            --cert client-cert.pem \
            --key client-key.pem \
            --cacert cacert.pem

Use **\--override-server-name** to overrides the server name used for hostname verification. Various access control flags exist to perform additional verification (on top of the regular hostname verification) of server certificates, such as **\--verify-cn**, **\--verify-ou**, **\--verify-dns**, **\--verify-uri**, or **\--verify-policy**. Multiple flags are treated as a logical disjunction (OR), meaning clients will connect to the server as long as any of the flags match, assuming that hostname verification was also successful. To disable sending client certificates, use **\--disable-authentication**.

# EXAMPLE: UNIX SOCKETS

Ghostunnel supports UNIX domain sockets for both listening and forwarding:

    # Server mode with UNIX socket
    ghostunnel server \
        --listen unix:/var/run/ghostunnel.sock \
        --target unix:/var/run/backend.sock \
        --keystore server-keystore.p12 \
        --cacert cacert.pem \
        --allow-cn client

    # Client mode with UNIX socket listener
    ghostunnel client \
        --listen unix:/var/run/client.sock \
        --target localhost:8443 \
        --keystore client-keystore.p12 \
        --cacert cacert.pem

UNIX sockets provide secure local communication without network exposure.

# EXAMPLE: STATUS AND METRICS

Enable status and metrics endpoints for monitoring and health checks:

    ghostunnel server \
        --listen localhost:8443 \
        --target localhost:8080 \
        --keystore server-keystore.p12 \
        --cacert cacert.pem \
        --allow-cn client \
        --status localhost:6060

Access status and metrics:

    # Status information (JSON)
    curl --cacert cacert.pem https://localhost:6060/_status

    # Metrics (Prometheus format)
    curl --cacert cacert.pem https://localhost:6060/_metrics/prometheus

    # Metrics (JSON format)
    curl --cacert cacert.pem https://localhost:6060/_metrics/json

The status port can also use HTTP by prefixing with \"http://\" (e.g., **\--status http://localhost:6060**). Profiling endpoints can be enabled with **\--enable-pprof**.

# EXAMPLE: MULTIPLE ACCESS CONTROL FLAGS

Multiple access control flags can be combined using OR logic:

    ghostunnel server \
        --listen localhost:8443 \
        --target localhost:8080 \
        --keystore server-keystore.p12 \
        --cacert cacert.pem \
        --allow-cn client1 \
        --allow-cn client2 \
        --allow-ou developers \
        --allow-uri spiffe://example.com/*

Clients matching any of the specified criteria (CN=client1 or CN=client2 or OU=developers or URI matching spiffe://example.com/\*) will be allowed to connect. The same OR logic applies to client mode verification flags (**\--verify-cn**, **\--verify-ou**, **\--verify-dns**, **\--verify-uri**).

# OPTIONS

**\--help** Show context-sensitive help (also try \--help-long and \--help-man).

**\--keystore=PATH** Path to keystore (combined PEM with cert/key, or PKCS12 keystore).

**\--cert=PATH** Path to certificate (PEM with certificate chain).

**\--key=PATH** Path to certificate private key (PEM with private key).

**\--storepass=PASS** Password for keystore (if using PKCS keystore, optional).

**\--cacert=CACERT** Path to CA bundle file (PEM/X509). Uses system trust store by default.

**\--use-workload-api** If true, certificate and root CAs are retrieved via the SPIFFE Workload API

**\--use-workload-api-addr=ADDR** If set, certificates and root CAs are retrieved via the SPIFFE Workload API at the specified address (implies \--use-workload-api)

**\--timed-reload=DURATION** Reload keystores every given interval (e.g. 300s), refresh listener/client on changes.

**\--shutdown-timeout=5m** Process shutdown timeout. Terminates after timeout even if connections still open.

**\--connect-timeout=10s** Timeout for establishing connections, handshakes.

**\--close-timeout=1s** Timeout for closing connections when one side terminates. Zero means immediate closure.

**\--max-conn-lifetime=0s** Maximum lifetime for connections post handshake, no matter what. Zero means infinite.

**\--max-concurrent-conns=0** Maximum number of concurrent connections to handle in the proxy. Zero means infinite.

**\--metrics-graphite=ADDR** Collect metrics and report them to the given graphite instance (raw TCP).

**\--metrics-url=URL** Collect metrics and POST them periodically to the given URL (via HTTP/JSON).

**\--metrics-prefix=PREFIX** Set prefix string for all reported metrics (default: ghostunnel).

**\--metrics-interval=30s** Collect (and post/send) metrics every specified interval.

**\--status=ADDR** Enable serving /\_status and /\_metrics on given HOST:PORT (or unix:SOCKET).

**\--enable-pprof** Enable serving /debug/pprof endpoints alongside /\_status (for profiling).

**\--enable-shutdown** Enable serving a /\_shutdown endpoint alongside /\_status to allow terminating via HTTP.

**\--quiet=** Silence log messages (can be all, conns, conn-errs, handshake-errs; repeat flag for more than one)

**\--skip-resolve** Skip resolving target host on startup (useful to start Ghostunnel before network is up).

**\--syslog** Send logs to syslog instead of stdout.

**\--keychain-identity=CN** Use local keychain identity with given serial/common name (instead of keystore file).

**\--keychain-issuer=CN** Use local keychain identity with given issuer name (instead of keystore file).

**\--keychain-require-token** Require keychain identity to be from a physical token (sets \'access group\' to \'token\').

**\--pkcs11-module=PATH** Path to PKCS11 module (SO) file (optional).

**\--pkcs11-token-label=LABEL** Token label for slot/key in PKCS11 module (optional).

**\--pkcs11-pin=PIN** PIN code for slot/key in PKCS11 module (optional).

**\--version** Show application version.

# COMMANDS

## **help \[\<command\>\...\]**

Show help.

## **server \--listen=ADDR \--target=ADDR \[\<flags\>\]**

Server mode (TLS listener -\> plain TCP/UNIX target). **\--listen=ADDR** Address and port to listen on (can be HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME).

**\--target=ADDR** Address to forward connections to (can be HOST:PORT or unix:PATH).

**\--target-status=\"\"** Address to target for status checking downstream healthchecks. Defaults to a TCP healthcheck if this flag is not passed.

**\--proxy-protocol** Enable PROXY protocol v2 to signal connection info to backend

**\--unsafe-target** If set, does not limit target to localhost, 127.0.0.1, \[::1\], or UNIX sockets.

**\--allow-all** Allow all clients, do not check client cert subject.

**\--allow-cn=CN** Allow clients with given common name (can be repeated).

**\--allow-ou=OU** Allow clients with given organizational unit name (can be repeated).

**\--allow-dns=DNS** Allow clients with given DNS subject alternative name (can be repeated).

**\--allow-uri=URI** Allow clients with given URI subject alternative name (can be repeated).

**\--allow-policy=BUNDLE** Allow passing the location of an OPA bundle.

**\--allow-query=QUERY** Allow defining a query to validate against the client certificate and the Rego policy.

**\--disable-authentication** Disable client authentication, no client certificate will be required.

**\--auto-acme-cert=FQDN** Automatically obtain a certificate via ACME for the specified FQDN

**\--auto-acme-email=EMAIL** Email address associated with all ACME requests

**\--auto-acme-agree-to-tos** Agree to the Terms of Service of the ACME CA

**\--auto-acme-ca=https://some-acme-ca.example.com/** Specify the URL to the ACME CA. Defaults to Let\'s Encrypt if not specified.

**\--auto-acme-testca=https://testing.some-acme-ca.example.com/** Specify the URL to the ACME CA\'s Test/Staging environment. If set, all requests will go to this CA and \--auto-acme-ca will be ignored.

## **client \--listen=ADDR \--target=ADDR \[\<flags\>\]**

Client mode (plain TCP/UNIX listener -\> TLS target). **\--listen=ADDR** Address and port to listen on (can be HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME).

**\--target=ADDR** Address to forward connections to (must be HOST:PORT).

**\--unsafe-listen** If set, does not limit listen to localhost, 127.0.0.1, \[::1\], or UNIX sockets.

**\--override-server-name=NAME** If set, overrides the server name used for hostname verification.

**\--proxy=URL** If set, connect to target over given proxy (HTTP CONNECT or SOCKS5). Must be a proxy URL.

**\--verify-cn=CN** Allow servers with given common name (can be repeated).

**\--verify-ou=OU** Allow servers with given organizational unit name (can be repeated).

**\--verify-dns=DNS** Allow servers with given DNS subject alternative name (can be repeated).

**\--verify-uri=URI** Allow servers with given URI subject alternative name (can be repeated).

**\--verify-policy=BUNDLE** Allow passing the location of an OPA bundle.

**\--verify-query=QUERY** Allow defining a query to validate against the client certificate and the Rego policy.

**\--disable-authentication** Disable client authentication, no certificate will be provided to the server.
