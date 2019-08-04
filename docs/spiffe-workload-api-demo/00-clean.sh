#!/bin/bash

set -e

# remove everything under spire/data except the .empty sentinels for git
find ./spire/data -type f -not -name .empty -delete
