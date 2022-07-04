#!/bin/bash

set -e

# Start up backend ghostunnel, verifying that connecting peers present the
# frontend SPIFFE ID.
ghostunnel server \
    --use-workload-api-addr "unix://${PWD}/spire/backend-agent.sock" \
    --listen=localhost:9002 \
    --target=localhost:9003 \
    --allow-uri spiffe://domain.test/frontend
