#!/bin/bash

set -e

# Start up frontend ghostunnel, verifying that server peer presents the
# backend SPIFFE ID.
ghostunnel client \
    --use-workload-api \
    --workload-api-addr "unix://${PWD}/spire/frontend-agent.sock" \
    --listen=localhost:9001 \
    --target=localhost:9002 \
    --verify-uri spiffe://domain.test/backend
