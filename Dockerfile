# Dockerfile for squareup/ghostunnel, useful as a basis for other images.
#
# To build this image:
#     docker build -t squareup/ghostunnel .
#
# To run ghostunnel from the image (for example):
#     docker run --rm squareup/ghostunnel ghostunnel --version
#
# For an example image that builds on top of this, check out the docker subdirectory.

FROM golang:alpine

MAINTAINER Cedric Staub "cs@squareup.com"

RUN apk add --update gcc musl-dev libtool

# Copy source
COPY . /go/src/github.com/square/ghostunnel

# Build & cleanup
RUN go build -o /usr/bin/ghostunnel github.com/square/ghostunnel && \
    rm -rf /go/src/*
