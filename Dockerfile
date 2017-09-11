# Dockerfile for squareup/ghostunnel, useful as a basis for other images.
#
# To build this image:
#     docker build -t squareup/ghostunnel .
#
# To run ghostunnel from the image (for example):
#     docker run --rm squareup/ghostunnel ghostunnel --version

FROM golang:alpine

MAINTAINER Cedric Staub "cs@squareup.com"

# Copy source
COPY . /go/src/github.com/square/ghostunnel

# Build & cleanup
RUN apk add --no-cache --update gcc musl-dev libtool && \
    go build -o /usr/bin/ghostunnel github.com/square/ghostunnel && \
    apk del gcc musl-dev && \
    rm -rf /go/src/* /go/pkg/* /var/cache/apk/*

ENTRYPOINT ["/usr/bin/ghostunnel"]
