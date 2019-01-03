# Dockerfile for squareup/ghostunnel, useful as a basis for other images.
#
# To build this image:
#     docker build -t squareup/ghostunnel .
#
# To run ghostunnel from the image (for example):
#     docker run --rm squareup/ghostunnel --version

FROM golang:1.11.4-alpine as build

MAINTAINER Cedric Staub "cs@squareup.com"

# Dependencies
RUN apk add --no-cache --update gcc musl-dev libtool

# Copy source
COPY . /go/src/github.com/square/ghostunnel

# Build
RUN go build -o /usr/bin/ghostunnel github.com/square/ghostunnel

# Create a multi-stage build with the binary
FROM alpine

RUN apk add --no-cache --update libtool curl
COPY --from=build /usr/bin/ghostunnel /usr/bin/ghostunnel

ENTRYPOINT ["/usr/bin/ghostunnel"]
