#!/bin/bash

set -e

# Refresh the bootstrap bundle
spire-server bundle show \
    -socketPath ./spire/server.sock > ./spire/bootstrap.crt

# Run the frontend agent
spire-agent run \
        -config ./spire/frontend-agent.conf \
        -joinToken "$(spire-server token generate -socketPath ./spire/server.sock -spiffeID spiffe://domain.test/frontend-agent | awk '{print $2}')"
