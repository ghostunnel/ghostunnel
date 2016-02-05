#!/bin/sh

REDIS_SOCKET=/tmp/redis.sock

# Launch ghostunnel
# Terminate redis if tunnel shuts down
(
  /go/bin/ghostunnel --listen 0.0.0.0:6379 --target unix:$REDIS_SOCKET "$@"
  redis-cli -s $REDIS_SOCKET shutdown
) &

# Launch redis
redis-server /etc/redis/redis.conf
