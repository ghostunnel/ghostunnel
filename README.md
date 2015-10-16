Ghostunnel
==========

[![license](http://img.shields.io/badge/license-apache_2.0-red.svg?style=flat)](https://raw.githubusercontent.com/square/ghostunnel/master/LICENSE) [![build](https://img.shields.io/travis/square/ghostunnel.svg?style=flat)](https://travis-ci.org/square/ghostunnel)

Ghostunnel is a simple SSL/TLS proxy with mutual authentication support for
securing non-TLS services such as redis. Ghostunnel runs in front of a backend
service and accepts TLS-secured connections, which are then forwarded to the
(insecure) backend. In other words, ghostunnel is a very limited replacement
for stunnel in server mode.

Features
========

***Certificate hotswapping***: Ghostunnel supports reloading certificates at
runtime without dropping existing connections. To trigger a reload, simply send
`SIGUSR1` to the process. This will cause ghostunnel to reload the cert/key
files and open a new listening socket (via `SO_REUSEPORT`). Once successful,
the old listening socket will be closed.

Ghostunnel can also reload certificates periodically. You can specify an
interval with the `--timed-reload` flag. If the timed reload flag is enabled,
ghostunnel will reload the files periodically and check for changes. If a
change is detected, it will attempt to reload the listener with the new
certificates/private key. 

***AuthN/AuthZ***: Ghostunnel always enforces AuthN by requiring a valid client
certificate. It also supports AuthZ via checks of the CN or OU fields on the 
subject of a connecting client certificate. To set allowed clients, you
must specify at least one of `--allow-all`, `--allow-cn` or `--allow-ou`. 
It's possible to use both `--allow-cn` and `--allow-ou` together or to 
specify them repeatedly to allow multiple CN/OU values.

Getting started
===============

To get started and play around with the implementation, you will need to 
generate some test certificates. If you want to bootstrap a full PKI, one
good way to get started is to use a package like
[square/certstrap](https://github.com/square/certstrap). If you only need
some test certificates for playing around with the tunnel, you can find
some pre-generated ones in the test-keys/ directory (alongside instructions
on how to generate new ones with OpenSSL).

### Launch ghostunnel

This is a short example for how to lunch ghostunnel listening for incoming
connections on localhost:8443 and forwarding them to localhost:8080. We
assume that server-keystore.p12 is a PKCS12 keystore with the cert and private
key for the server, ca-bundle.crt contains your trusted root certificates,
and the OU of the client cert to accept connections from is "client".

Start a ghostunnel with a server certificate:

    ghostunnel \
        --listen 127.0.0.1:8443 \
        --target 127.0.0.1:8080 \
        --keystore server-keystore.p12 \
        --cacert ca-bundle.crt \
        --allow-ou client

Verify that the client(s) can connect with their client certificate:

    openssl s_client \
        -connect 127.0.0.1:8443 \
        -cert client.crt \
        -key client.key \
        -CAfile ca-bundle.crt

If `openssl s_client` can connect, then the tunnel should be working as
intended! Be sure to check the logs to see incoming connections and other
information. Note that by default ghostunnel logs to stderr and runs in the
foreground.  For deamonization, we recommend using a utility such as
[daemonize](http://software.clapper.org/daemonize/). Ghostunnel supports
logging to syslog with the `--syslog` flag.
