#!/bin/bash

set -e

# Refresh the bootstrap bundle
spire-server bundle show \
    -registrationUDSPath ./spire/server.sock > ./spire/bootstrap.crt

# Run the backend agent
spire-agent run \
        -config ./spire/backend-agent.conf \
        -joinToken "$(spire-server token generate -registrationUDSPath ./spire/server.sock -spiffeID spiffe://domain.test/backend-agent | awk '{print $2}')"
