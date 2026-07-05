# go-proxyproto

[![Actions Status](https://github.com/pires/go-proxyproto/workflows/test/badge.svg)](https://github.com/pires/go-proxyproto/actions)
[![Coverage Status](https://coveralls.io/repos/github/pires/go-proxyproto/badge.svg?branch=main)](https://coveralls.io/github/pires/go-proxyproto?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/pires/go-proxyproto)](https://goreportcard.com/report/github.com/pires/go-proxyproto)
[![](https://godoc.org/github.com/pires/go-proxyproto?status.svg)](https://pkg.go.dev/github.com/pires/go-proxyproto?tab=doc)


A Go library implementation of the [PROXY protocol, versions 1 and 2](https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt),
which provides, as per specification:
> (...) a convenient way to safely transport connection
> information such as a client's address across multiple layers of NAT or TCP
> proxies. It is designed to require little changes to existing components and
> to limit the performance impact caused by the processing of the transported
> information.

This library is to be used in one of or both proxy clients and proxy servers that need to support said protocol.
Both protocol versions, 1 (text-based) and 2 (binary-based) are supported.

## Installation

```shell
$ go get -u github.com/pires/go-proxyproto
```

## Examples

The fastest way to get started is the runnable programs under
[`examples/`](examples) and the API examples on
[pkg.go.dev](https://pkg.go.dev/github.com/pires/go-proxyproto#pkg-examples):

| Goal | Where to look |
| ---- | ------------- |
| Minimal client | [`examples/client`](examples/client) |
| Minimal server | [`examples/server`](examples/server) |
| HTTP server | [`examples/httpserver`](examples/httpserver) |
| Server + client over TLS (PROXY header before TLS) | [`examples/tlsserver`](examples/tlsserver), [`examples/tlsclient`](examples/tlsclient) |
| `Listener` options: timeout, buffer size, policy, validation | [`ExampleListener_*`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener) |
| `NewConn` options | [`ExampleNewConn_*`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-NewConn) |
| PROXY over TLS, both wrapping orders | [`ExampleListener_tls`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-Tls), [`ExampleListener_tlsHeaderInsideTLS`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-TlsHeaderInsideTLS) |

## Usage

Use the full runnable examples above for complete programs. The core API shape is
small:

### Client side

```go
header := proxyproto.HeaderProxyFromAddrs(1, sourceAddr, destinationAddr)
_, err := header.WriteTo(conn) // write the PROXY header before application data
```

See [`examples/client`](examples/client) for a complete TCP client.

### Server side

```go
proxyListener := &proxyproto.Listener{Listener: ln}
conn, err := proxyListener.Accept()
// conn.RemoteAddr() now reports the client address from the PROXY header, when present.
```

See [`examples/server`](examples/server) for a complete TCP server. For HTTP/1
and HTTP/2, see [`examples/httpserver`](examples/httpserver), which uses
[`helper/http2`](helper/http2) so one server can accept proxied HTTP/1 and HTTP/2
connections.

### TLS

When combining the PROXY protocol with TLS, choose the wrapping order based on
where the upstream puts the PROXY header relative to the TLS handshake:

- **Header in cleartext, before the handshake**: proxyproto reads the header
  first, so it goes inside the TLS listener:
  `tls.NewListener(&proxyproto.Listener{Listener: l}, tlsConfig)`.
- **Header inside the TLS session, after the handshake**: TLS decrypts first, so
  proxyproto wraps the TLS listener:
  `&proxyproto.Listener{Listener: tls.NewListener(l, tlsConfig)}`.

In both cases `conn.RemoteAddr()` reports the client carried by the PROXY
header. Runnable code lives in [`examples/tlsserver`](examples/tlsserver) and
[`examples/tlsclient`](examples/tlsclient); the API examples
[`ExampleListener_tls`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-Tls)
and
[`ExampleListener_tlsHeaderInsideTLS`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-TlsHeaderInsideTLS)
show both orderings.

## Special notes

### AWS

AWS Network Load Balancer (NLB) does not push the PPV2 header until the client starts sending the data. This is a problem if your server speaks first. e.g. SMTP, FTP, SSH etc.

By default, NLB target group attribute `proxy_protocol_v2.client_to_server.header_placement` has the value `on_first_ack_with_payload`. You need to contact AWS support to change it to `on_first_ack`, instead.

Just to be clear, you need this fix only if your server is designed to speak first.
