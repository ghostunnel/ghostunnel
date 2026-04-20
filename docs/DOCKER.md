---
title: Docker Images
description: Available Docker image variants and tags for running Ghostunnel in containers.
weight: 85
---

Docker images are published to [Docker Hub][hub] on each release. Three
variants are available:

| Variant | Tag | Base |
|---------|-----|------|
| Alpine | `ghostunnel/ghostunnel:latest-alpine`, `ghostunnel/ghostunnel:v1.x.x-alpine` | Alpine Linux |
| Debian | `ghostunnel/ghostunnel:latest-debian`, `ghostunnel/ghostunnel:v1.x.x-debian` | Debian Slim |
| Distroless | `ghostunnel/ghostunnel:latest-distroless`, `ghostunnel/ghostunnel:v1.x.x-distroless` | Distroless (`gcr.io/distroless/base-nossl:nonroot`) |

The `latest` tags always point to the most recent release.

## Pulling an Image

```bash
# Distroless (smallest, no shell)
docker pull ghostunnel/ghostunnel:latest-distroless

# Alpine (includes shell, good for debugging)
docker pull ghostunnel/ghostunnel:latest

# Debian (includes shell and package manager)
docker pull ghostunnel/ghostunnel:latest-debian
```

## Running in Docker

Mount your certificate files into the container and pass flags as normal:

```bash
docker run --rm \
    -v /path/to/certs:/certs:ro \
    -p 8443:8443 \
    ghostunnel/ghostunnel:latest-distroless \
    server \
    --listen 0.0.0.0:8443 \
    --target host.docker.internal:8080 \
    --cert /certs/server-cert.pem \
    --key /certs/server-key.pem \
    --cacert /certs/cacert.pem \
    --allow-cn client
```

Note the use of `0.0.0.0` for `--listen` (to bind all interfaces inside the
container) and `host.docker.internal` for `--target` (to reach services on
the Docker host). You may need `--unsafe-target` since `host.docker.internal`
is not localhost.

## Building Images from Source

```bash
go tool mage docker:build
```

[hub]: https://hub.docker.com/r/ghostunnel/ghostunnel
