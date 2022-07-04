#!/bin/bash

USER_NAME="$USERDOMAIN\\$USERNAME"

# Register the backend ghostunnel
./spire-server.exe entry create \
    -selector windows:user_name:${USER_NAME} \
    -namedPipeName \\spire-server\\private\\api \
    -spiffeID spiffe://domain.test/backend  \
    -parentID spiffe://domain.test/backend-agent

# Register the frontend ghostunnel
./spire-server.exe entry create \
    -selector windows:user_name:${USER_NAME} \
    -namedPipeName \\spire-server\\private\\api \
    -spiffeID spiffe://domain.test/frontend  \
    -parentID spiffe://domain.test/frontend-agent
