#!/bin/sh

REDIS_CONFIG='/etc/redis.conf'
REDIS_SOCKET=`grep 'unixsocket .*' $REDIS_CONFIG | cut -d' ' -f2`

# Launch redis
redis-server $REDIS_CONFIG &

while ! [ -S $REDIS_SOCKET ]; do
  echo "Waiting for $REDIS_SOCKET to appear..."
  sleep 1
done

# Launch ghostunnel
# Terminate redis if tunnel shuts down
(
  ghostunnel --listen 0.0.0.0:6379 --target unix:$REDIS_SOCKET "$@"
  redis-cli -s $REDIS_SOCKET shutdown
) &

# Wait for redis; terminate tunnel if redis stops
wait %1
kill %2
