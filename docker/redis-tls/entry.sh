#!/bin/sh

REDIS_CONFIG='/etc/redis.conf'
REDIS_SOCKET=`grep 'unixsocket .*' $REDIS_CONFIG | cut -d' ' -f2`

exec ghostunnel server --listen 0.0.0.0:6379 --target unix:$REDIS_SOCKET "$@" -- redis-server $REDIS_CONFIG
