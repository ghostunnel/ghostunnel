#!/bin/bash

set -e

# Refresh the bootstrap bundle
./spire-server.exe bundle show \
    -namedPipeName \\spire-server\\private\\api > ./spire/bootstrap.crt

# Run the frontend agent
./spire-agent.exe run \
    -config ./spire/frontend-agent.conf \
    -joinToken "$(./spire-server.exe token generate -namedPipeName \\spire-server\\private\\api -spiffeID spiffe://domain.test/frontend-agent | awk '{print $2}')"
