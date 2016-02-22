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

# Install dependencies
RUN apk add --update make git && go get github.com/Masterminds/glide

# Build ghostunnel
COPY . /go/src/ghostunnel
RUN cd /go/src/ghostunnel && make build && cp ghostunnel /usr/bin && rm -rf /go/src/*
