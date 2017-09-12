# Dockerfile for running integration tests, includes PKCS11/SoftHSM setup. 
# 
# Build image:
#     docker build --build-arg GO_VERSION=[VERSION] -t squareup/ghostunnel-test -f Dockerfile-test .
#
# Run integration tests:
#     docker run -v /dev/log:/dev/log -v $PWD:/go/src/github.com/square/ghostunnel squareup/ghostunnel-test

ARG GO_VERSION

FROM golang:${GO_VERSION}

MAINTAINER Cedric Staub "cs@squareup.com"

# Install build dependencies
RUN apt-get update && \
    apt-get install --yes build-essential libtool python3.5 netcat softhsm2 rsyslog && \
    mkdir -p /etc/softhsm /var/lib/softhsm/tokens /go/src/github.com/square/ghostunnel && \
    ln -s /usr/bin/python3.5 /usr/bin/python3 && \
    go get github.com/wadey/gocovmerge && \
    go get golang.org/x/tools/cmd/cover

WORKDIR /go/src/github.com/square/ghostunnel

# Setup SoftHSM for testing PKCS11 support
# Instruct PKCS11 integration test to run
ENV GHOSTUNNEL_TEST_PKCS11=true

# Set params for PKCS11 module
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
ENV PKCS11_LABEL=ghostunnel-pkcs11-test
ENV PKCS11_PIN=1234

# Set SoftHSM config file
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

ENTRYPOINT ["/usr/bin/make"]
CMD ["clean", "softhsm-import", "test"]
