# Dockerfile for ghostunnel/ghostunnel, useful as a basis for other images.
#
# To run ghostunnel from the image (for example):
#     docker run --rm ghostunnel/ghostunnel --version

FROM gcr.io/distroless/base

ARG TARGETPLATFORM

COPY dist/${TARGETPLATFORM}/ghostunnel /usr/bin/ghostunnel

ENTRYPOINT ["/usr/bin/ghostunnel"]
