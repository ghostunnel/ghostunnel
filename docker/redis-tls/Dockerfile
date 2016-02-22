# Dockerfile for redis with ghostunnel as SSL/TLS proxy.
#
# To build this image:
#     docker build -t redis-tls .
#
# To run, with given arguments to terminate TLS connections (for example):
#     docker run \
#       --name redis-tls \
#       -p 6379:6379 \
#       -v $SECRETS_PATH:/secrets \
#       redis-tls \
#       --keystore=/secrets/server-keystore.p12 \
#       --cacert=/secrets/ca-bundle.crt \
#       --allow-cn client

FROM square/ghostunnel

MAINTAINER Cedric Staub "cs@squareup.com"

# Install redis from alpine repositories
RUN apk add --update redis

# Configure redis to listen on UNIX socket
RUN \
  sed -i 's/^\(bind .*\)$/# \1/' /etc/redis.conf && \
  sed -i 's/^\(daemonize .*\)$/# \1/' /etc/redis.conf && \
  sed -i 's/^\(dir .*\)$/dir \/data/' /etc/redis.conf && \
  sed -i 's/^\(logfile .*\)$/# \1/' /etc/redis.conf && \
  sed -i 's/^\(port .*\)$/port 0/' /etc/redis.conf && \
  sed -i 's/^# \(unixsocket .*\)$/\1/' /etc/redis.conf && \
  sed -i 's/^# \(unixsocketperm .*\)$/\1/' /etc/redis.conf && \
  mkdir -p /data && chown -R redis:redis /data

# Define mountable directories.
VOLUME ["/data"]

# Define working directory.
WORKDIR /data

# Drop privs to non-root
USER redis

# Define default command.
COPY entry.sh /entry.sh
ENTRYPOINT ["/entry.sh"]

# Expose ports.
EXPOSE 6379
