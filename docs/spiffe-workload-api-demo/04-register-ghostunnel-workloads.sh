#!/bin/bash

# Register the backend ghostunnel
spire-server entry create \
    -selector unix:uid:${UID} \
    -registrationUDSPath ./spire/server.sock \
    -spiffeID spiffe://domain.test/backend  \
    -parentID spiffe://domain.test/backend-agent

# Register the frontend ghostunnel
spire-server entry create \
    -selector unix:uid:${UID} \
    -registrationUDSPath ./spire/server.sock \
    -spiffeID spiffe://domain.test/frontend  \
    -parentID spiffe://domain.test/frontend-agent
