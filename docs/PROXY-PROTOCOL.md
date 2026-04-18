---
title: PROXY Protocol
description: Pass original client connection metadata (IP, TLS version, client certificate) through to plaintext backends using HAProxy's PROXY protocol v2.
weight: 55
---

When Ghostunnel terminates TLS, the backend only sees a plaintext connection
from Ghostunnel itself. It has no idea who the original client was, what TLS
version was negotiated, or whether a client certificate was presented. The PROXY
protocol fixes this: Ghostunnel prepends a small binary header to each
forwarded connection carrying the original client metadata. Backends can then
do logging, access control, or auditing based on client identity without
needing their own TLS stack.

### Enabling

See [Command-Line Flags]({{< ref "FLAGS.md" >}}) for the full flag reference.

Pass `--proxy-protocol` in server mode to enable PROXY protocol v2 with
connection info (source/destination IP and port):

```bash
ghostunnel server \
  --listen=:8443 \
  --target=localhost:8080 \
  --keystore=server.p12 \
  --cacert=ca.crt \
  --allow-ou=my-service \
  --proxy-protocol
```

To also include TLS metadata and/or client certificate details, use the
`--proxy-protocol-mode` flag:

| Mode | What is sent |
|------|-------------|
| `conn` | Connection info only (src/dst IP+port). Same as bare `--proxy-protocol`. |
| `tls` | Connection info + TLS metadata (version, ALPN, SNI). No client cert details. |
| `tls-full` | Connection info + TLS metadata + full client certificate details. |

```bash
# TLS metadata without client cert:
ghostunnel server ... --proxy-protocol-mode=tls

# Everything, including client cert:
ghostunnel server ... --proxy-protocol-mode=tls-full
```

Using `--proxy-protocol-mode` implies `--proxy-protocol`; you do not need to
pass both.

The backend will receive a PROXY protocol v2 binary header on each new
connection, followed by the normal application data stream.

### What Ghostunnel sends

Ghostunnel sends a **version 2** (binary format) header with the `PROXY`
command. The address family (IPv4 or IPv6) is detected from the incoming
connection.

#### Address fields (all modes)

| Field | Value |
|-------|-------|
| Source address/port | Original client IP and port |
| Destination address/port | Ghostunnel's listen IP and port |

#### TLV extensions (`tls` and `tls-full` modes)

When using `--proxy-protocol-mode=tls` or `--proxy-protocol-mode=tls-full`,
Ghostunnel includes TLV (Type-Length-Value) extensions with TLS connection
metadata:

| TLV | Type | Description |
|-----|------|-------------|
| `PP2_TYPE_SSL` | `0x20` | Container for SSL/TLS metadata (see below) |
| `PP2_TYPE_AUTHORITY` | `0x02` | SNI hostname the client requested (if set) |
| `PP2_TYPE_ALPN` | `0x01` | Negotiated ALPN protocol, e.g. `h2` (if set) |

#### SSL sub-TLVs

The `PP2_TYPE_SSL` TLV contains a 5-byte sub-header followed by nested
sub-TLVs:

**Sub-header:**

| Field | Size | Description |
|-------|------|-------------|
| Client flags | 1 byte | Bitfield: `0x01` = SSL used, `0x02` = client cert on connection, `0x04` = client cert on session |
| Verify result | 4 bytes | `0` = certificate verified successfully |

**Nested sub-TLVs (always present in `tls` and `tls-full` modes):**

| Sub-TLV | Type | Example value |
|---------|------|---------------|
| `PP2_SUBTYPE_SSL_VERSION` | `0x21` | `TLS 1.3` |

**Nested sub-TLVs (`tls-full` mode only, when a client certificate was provided):**

| Sub-TLV | Type | Description |
|---------|------|-------------|
| `PP2_SUBTYPE_SSL_CN` | `0x22` | Client certificate Common Name |
| `PP2_SUBTYPE_SSL_CLIENT_CERT` | `0x28` | Full client certificate in DER (ASN.1) encoding |

The `tls-full` mode is useful when backends need to perform their own access
control or auditing based on client certificate identity. See [Access Control
Flags]({{< ref "ACCESS-FLAGS.md" >}}) for how Ghostunnel itself verifies
client certificates before forwarding.

Note: `PP2_SUBTYPE_SSL_CLIENT_CERT` (`0x28`) is not part of the original
HAProxy spec but is supported by the
[go-proxyproto](https://github.com/pires/go-proxyproto) library and others.
The spec requires receivers to ignore unknown TLV types, so this is safe.

### Backend requirements

Your backend must be configured to expect PROXY protocol headers. It needs to
parse the binary header before reading application data. Most servers and
frameworks support this:

- **nginx**: `proxy_protocol` parameter on `listen` directive
- **Apache**: `mod_remoteip` with `RemoteIPProxyProtocol`
- **HAProxy**: `accept-proxy` on `bind` lines
- **Custom apps**: use a PROXY protocol parsing library for your language

Backends that aren't expecting PROXY protocol will see the binary header as
garbage at the start of the stream and will reject the connection.

### References

- [PROXY protocol specification](https://www.haproxy.org/download/3.1/doc/proxy-protocol.txt) (HAProxy, covers v1 and v2; see section 2.2 for the TLV type registry)
- [go-proxyproto](https://github.com/pires/go-proxyproto) (Go library used by Ghostunnel)
