#!/bin/bash

set -e

# Start up frontend ghostunnel, verifying that server peer presents the
# backend SPIFFE ID.
./ghostunnel.exe client \
    --use-workload-api-addr "npipe:frontend-agent\public\api" \
    --listen=localhost:9001 \
    --target=localhost:9002 \
    --verify-uri spiffe://domain.test/backend
