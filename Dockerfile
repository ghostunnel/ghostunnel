# Dockerfile for ghostunnel/ghostunnel, useful as a basis for other images.
#
# To build this image:
#     docker build -t ghostunnel/ghostunnel .
#
# To run ghostunnel from the image (for example):
#     docker run --rm ghostunnel/ghostunnel --version

FROM golang:1.14.7-alpine as build

# Dependencies
RUN apk add --no-cache --update gcc musl-dev libtool make git

# Copy source
COPY . /go/src/github.com/ghostunnel/ghostunnel

# Build
RUN cd /go/src/github.com/ghostunnel/ghostunnel && \
    GO111MODULE=on make clean ghostunnel && \
    cp ghostunnel /usr/bin/ghostunnel

# Create a multi-stage build with the binary
FROM alpine

RUN apk add --no-cache --update libtool curl
COPY --from=build /usr/bin/ghostunnel /usr/bin/ghostunnel

ENTRYPOINT ["/usr/bin/ghostunnel"]
