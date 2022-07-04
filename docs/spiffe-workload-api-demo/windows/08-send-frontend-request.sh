#!/bin/bash

set -e

# Send STDIN to localhost port 9001 (the frontend ghostunnel)
echo "Hi from the frontend!" | socat STDIN TCP:localhost:9001
