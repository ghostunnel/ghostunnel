Ghostunnel
==========

[![license](http://img.shields.io/badge/license-apache_2.0-red.svg?style=flat)](https://raw.githubusercontent.com/square/ghostunnel/master/LICENSE)

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

Ghostunnel can also reload certificates automatically via inotify/fswatch,
which can be enabled with the `--auto-reload` flag. If you want to do without
inotify/fswatch, ghostunnel also supports periodically reloading cert/key files
from disk at a specified interval with the `--timed-reload` flag.

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
some test certificates for playing around with the tunnel, OpenSSL can
be used to generate them.

### Generate test keys

You must first generate a root certificate:

    openssl genrsa -out root.key 1024
    openssl req -x509 -new -key root.key -days 5 -out root.crt -subj /C=US/ST=CA/O=ghostunnel/OU=root

Configure OpenSSL to set extensions and subject alt names:

    cat >openssl.ext <<EOF
    extendedKeyUsage = clientAuth, serverAuth
    subjectAltName = IP:127.0.0.1,IP:::1
    EOF

Finally you can sign server and client certificates:

    openssl genrsa -out server.key 1024
    openssl req -new -key server.key -out server.csr -subj /C=US/ST=CA/O=ghostunnel/OU=server
    openssl x509 -req -in server.csr -CA root.crt -CAkey root.key -CAcreateserial -out server.crt -days 5 -extfile openssl.ext
    openssl pkcs12 -export -out server.p12 -in server.crt -inkey server.key -password pass:

    openssl genrsa -out server.key 1024
    openssl req -new -key client.key -out client.csr -subj /C=US/ST=CA/O=ghostunnel/OU=client
    openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 5 -extfile openssl.ext
    openssl pkcs12 -export -out client.p12 -in client.crt -inkey client.key -password pass:

### Launch ghostunnel

Start a ghostunnel with a server certificate:

    ghostunnel --listen 127.0.0.1:8443 --target 127.0.0.1:8080 --keystore server.p12 --cacert root.crt --allow-ou client

Verify that the client(s) can connect with their client certificate:

    openssl s_client -connect 127.0.0.1:8443 -cert client.crt -key client.key -CAfile root.crt

