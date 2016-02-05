#!/bin/sh

REDIS_USER=redis
REDIS_SOCKET=/tmp/redis.sock

# Launch ghostunnel
# Terminate redis if tunnel shuts down
(
  sudo -u $REDIS_USER /go/bin/ghostunnel --listen 0.0.0.0:6379 --target unix:$REDIS_SOCKET "$@"
  redis-cli -s $REDIS_SOCKET shutdown
) &

# Launch redis
sudo -u $REDIS_USER redis-server /etc/redis/redis.conf
