# Dockerfile for redis with ghostunnel as SSL/TLS proxy.
#
# This is a fork of dockerfile/redis, licensed under:
# -----------------------------------------------------------------------------
# The MIT License (MIT)
# 
# Copyright (c) Dockerfile Project
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# -----------------------------------------------------------------------------

FROM golang 

MAINTAINER Cedric Staub "cs@squareup.com"

# Install redis.
RUN \
  cd /tmp && \
  wget http://download.redis.io/redis-stable.tar.gz && \
  tar xvzf redis-stable.tar.gz && \
  cd redis-stable && \
  make && \
  make install && \
  cp -f src/redis-sentinel /usr/local/bin && \
  mkdir -p /etc/redis && \
  cp -f *.conf /etc/redis && \
  rm -rf /tmp/redis-stable* && \
  sed -i 's/^\(bind .*\)$/# \1/' /etc/redis/redis.conf && \
  sed -i 's/^\(daemonize .*\)$/# \1/' /etc/redis/redis.conf && \
  sed -i 's/^\(dir .*\)$/# \1\ndir \/data/' /etc/redis/redis.conf && \
  sed -i 's/^\(logfile .*\)$/# \1/' /etc/redis/redis.conf && \
  sed -i 's/^\(port .*\)$/# \1/' /etc/redis/redis.conf

# Configure redis to listen on UNIX socket.
RUN echo "port 0" >> /etc/redis/redis.conf
RUN echo "unixsocket /tmp/redis.sock" >> /etc/redis/redis.conf
RUN echo "unixsocketperm 700" >> /etc/redis/redis.conf

RUN useradd -ms /bin/false redis

# Install ghostunnel.
RUN mkdir /ghostunnel
COPY run.sh /ghostunnel/run.sh
RUN go get github.com/square/ghostunnel

# Install sudo.
RUN apt-get update && apt-get install -y sudo --no-install-recommends

# Define mountable directories.
VOLUME ["/data"]

# Define working directory.
WORKDIR /data

# Define default command.
ENTRYPOINT ["/ghostunnel/run.sh"]

# Expose ports.
EXPOSE 6379
