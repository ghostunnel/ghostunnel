# Dockerfile for square/ghostunnel, useful as a basis for other images.
#
# To build this image:
#     docker build -t square/ghostunnel .
#
# To run ghostunnel from the image (for example):
#     docker run --rm square/ghostunnel ghostunnel --version
#
# For an example image that builds on top of this, check out the docker subdirectory.

FROM golang:alpine

MAINTAINER Cedric Staub "cs@squareup.com"

# Copy source
COPY . /go/src/github.com/square/ghostunnel

# Build & cleanup
RUN go build -o /usr/bin/ghostunnel github.com/square/ghostunnel && \
    rm -rf /go/src/*
