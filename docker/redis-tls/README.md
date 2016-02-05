Redis with ghostunnel
=====================

This directory contains a Dockerfile for building a Docker container that
runs redis with ghostunnel as a SSL/TLS proxy. It serves as an example for how
use ghostunnel to proxy connections to applications that do not natively
support SSL/TLS.

### Building

To build the container:

    docker build -t redis-tls .

### Running 

In this example, we assume that the $SECRETS_PATH directory contains your
keystore and root certificate for the ghostunnel instance, and that the CN of
clients you want to allow is `client`.

To launch the container in the foreground:

    docker run \
      --name redis-tls \
      -p 6379:6379 \
      -v $SECRETS_PATH:/secrets \
      redis-tls \
      --keystore=/secrets/server-keystore.p12 \
      --cacert=/secrets/ca-bundle.crt \
      --allow-cn client

See also https://github.com/dockerfile/redis
