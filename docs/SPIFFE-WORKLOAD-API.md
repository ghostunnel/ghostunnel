SPIFFE Workload API Support
===================

Ghostunnel has support for the [SPIFFE](https://spiffe.io)
[Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
Using the Workload API, Ghostunnel maintains up-to-date, frequently rotated
client/server identities (i.e. X.509 certificates and private keys) and trusted
X.509 roots. When utilizing the Workload API, ghosttunnel expects peers to
present SPIFFE
[X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
and verifies them using SPIFFE authentication.

To enable workload API support, use the `--use-workload-api` flag. By default,
the location of the SPIFFE Workload API socket is picked up from the
`SPIFFE_ENDPOINT_SOCKET` environment variable. The `--workload-api-addr` flag
can be used to explicitly set the address, like so:

UNIX: 
```
$ ghostunnel server \
    --use-workload-api-addr /run/spire/sockets/agent.sock \
    ... other server options ...
```

Windows:
```
$ ghostunnel server \
    --use-workload-api-addr npipe:spire-agent\\public\\api \
    ... other server options ...
```

Authorization
-------------------

The identity of the peer, i.e. the [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md), is embedded as a URI SAN on the
X509-SVID. Accordingly, the existing `--verify-uri` and `--allow-uri`
flags can be used to authorize the peer:

As a server:

```
$ ghostunnel server \
    --use-workload-api \
    --listen localhost:8443 \
    --target localhost:8080 \
    --allow-uri spiffe://domain.test/frontend
```

As a client, 

```
$ ghostunnel client \
    --use-workload-api \
    --listen localhost:8080 \
    --target localhost:8443 \
    --verify-uri spiffe://domain.test/backend
```

Demo
-------------------

See the [end-to-end demo](spiffe-workload-api-demo/README.md) for an example
using Ghostunnel with SPIFFE Workload API support backed by
[SPIRE](https://spiffe.io/spire/).
