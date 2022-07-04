#!/bin/bash

set -e

# Run SPIRE server
spire-server run -config ./spire/server.conf
