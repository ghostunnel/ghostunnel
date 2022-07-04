#!/bin/bash

set -e

# The backend listens on port 9003 and writes data to STDOUT
socat TCP-LISTEN:9003,fork STDOUT
