#!/bin/bash

set -e

# Start up backend ghostunnel, verifying that connecting peers present the
# frontend SPIFFE ID.
./ghostunnel.exe server \
    --use-workload-api-addr "npipe:backend-agent\public\api" \
    --listen=localhost:9002 \
    --target=localhost:9003 \
    --allow-uri spiffe://domain.test/frontend
