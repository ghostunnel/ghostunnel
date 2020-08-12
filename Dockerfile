# Dockerfile for ghostunnel/ghostunnel, useful as a basis for other images.
#
# To build this image:
#     docker build -t ghostunnel/ghostunnel .
#
# To run ghostunnel from the image (for example):
#     docker run --rm ghostunnel/ghostunnel --version

FROM debian:buster-slim

ARG ARCH
ARG VERSION

COPY dist/ghostunnel-${VERSION}-linux-${ARCH}-with-pkcs11 /usr/bin/ghostunnel
RUN chmod +x /usr/bin/ghostunnel

ENTRYPOINT ["/usr/bin/ghostunnel"]
