# Dockerfile for squareup/ghostunnel, useful as a basis for other images.
#
# To build this image:
#     docker build -t squareup/ghostunnel .
#
# To run ghostunnel from the image (for example):
#     docker run --rm squareup/ghostunnel --version

FROM golang:1.12.6-alpine as build

MAINTAINER Cedric Staub "cs@squareup.com"

# Dependencies
RUN apk add --no-cache --update gcc musl-dev libtool

# Copy source
COPY . /go/src/github.com/square/ghostunnel

# Build
RUN cd /go/src/github.com/square/ghostunnel && \
    GO111MODULE=on make ghostunnel && \
    cp ghostunnel /usr/bin/ghostunnel

# Create a multi-stage build with the binary
FROM alpine

RUN apk add --no-cache --update libtool curl
COPY --from=build /usr/bin/ghostunnel /usr/bin/ghostunnel

ENTRYPOINT ["/usr/bin/ghostunnel"]
